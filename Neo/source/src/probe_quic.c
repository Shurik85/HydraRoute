#include "../include/probe_quic.h"
#include "../include/probe_tls.h"
#include "../include/quic_crypto.h"
#include <string.h>
#include <stdint.h>

#define QUIC_V1 0x00000001u
#define QUIC_V2 0x6b3343cfu
#define QUIC_CH_REC_MAX 8192

static const uint8_t SALT_V1[20] = {
    0x38,0x76,0x2c,0xf7,0xf5,0x59,0x34,0xb3,0x4d,0x17,
    0x9a,0xe6,0xa4,0xc8,0x0c,0xad,0xcc,0xbb,0x7f,0x0a
};
static const uint8_t SALT_V2[20] = {
    0x0d,0xed,0xe3,0xde,0xf7,0x00,0xa6,0xdb,0x81,0x93,
    0x81,0xbe,0x6e,0x26,0x9d,0xcb,0xf9,0xbd,0x2e,0xd9
};

static int read_varint(const uint8_t *buf, size_t len, size_t *pos, uint64_t *val) {
    if (*pos >= len) return 0;
    uint8_t first = buf[*pos];
    size_t vlen = (size_t)(1u << (first >> 6));
    if (*pos + vlen > len) return 0;
    *val = first & 0x3Fu;
    for (size_t i = 1; i < vlen; i++)
        *val = (*val << 8) | buf[*pos + i];
    *pos += vlen;
    return 1;
}

int quic_ch_to_sni(const uint8_t *ch, size_t ch_len, char *host, size_t host_size) {
    if (ch_len < 6 || ch_len + 5 > QUIC_CH_REC_MAX) return 0;
    static uint8_t rec[QUIC_CH_REC_MAX];
    rec[0] = 0x16; rec[1] = 0x03; rec[2] = 0x01;
    rec[3] = (uint8_t)(ch_len >> 8);
    rec[4] = (uint8_t)(ch_len);
    memcpy(rec + 5, ch, ch_len);
    return tls_extract_sni(rec, ch_len + 5, host, host_size);
}

int quic_extract_sni(const uint8_t *pkt, int pkt_len, char *host, size_t host_size,
                     quic_crypto_frag_t *frag) {
    if (frag) frag->found = 0;
    if (pkt_len < 20) return 0;
    if ((pkt[0] & 0xC0) != 0xC0) return 0;

    uint32_t version = ((uint32_t)pkt[1] << 24) | ((uint32_t)pkt[2] << 16) |
                       ((uint32_t)pkt[3] <<  8) |  (uint32_t)pkt[4];

    const uint8_t *salt;
    if (version == QUIC_V1) {
        if ((pkt[0] & 0x30) != 0x00) return 0;
        salt = SALT_V1;
    } else if (version == QUIC_V2) {
        if ((pkt[0] & 0x30) != 0x10) return 0;
        salt = SALT_V2;
    } else {
        return 0;
    }

    size_t pos = 5;

    if ((size_t)pkt_len < pos + 1) return 0;
    uint8_t dcil = pkt[pos++];
    if (dcil > 20 || (size_t)pkt_len < pos + dcil) return 0;
    const uint8_t *dcid = pkt + pos;
    pos += dcil;

    if ((size_t)pkt_len < pos + 1) return 0;
    uint8_t scil = pkt[pos++];
    if (scil > 20 || (size_t)pkt_len < pos + scil) return 0;
    pos += scil;

    uint64_t token_len;
    if (!read_varint(pkt, (size_t)pkt_len, &pos, &token_len)) return 0;
    if (pos + (size_t)token_len > (size_t)pkt_len) return 0;
    pos += (size_t)token_len;

    uint64_t payload_len;
    if (!read_varint(pkt, (size_t)pkt_len, &pos, &payload_len)) return 0;
    if (payload_len < 20 || pos + (size_t)payload_len > (size_t)pkt_len) return 0;

    size_t pn_offset = pos;

    uint8_t initial_secret[32], client_secret[32];
    uint8_t key[16], iv[12], hp[16];

    hkdf_extract(salt, 20, dcid, dcil, initial_secret);
    hkdf_expand_label(initial_secret, "client in", client_secret, 32);
    hkdf_expand_label(client_secret, "quic key", key, 16);
    hkdf_expand_label(client_secret, "quic iv",  iv,  12);
    hkdf_expand_label(client_secret, "quic hp",  hp,  16);

    const uint8_t *sample = pkt + pn_offset + 4;
    uint8_t mask[16];
    aes128_ecb_encrypt(hp, sample, mask);

    uint8_t first_byte = pkt[0] ^ (mask[0] & 0x0F);
    uint8_t pn_len = (first_byte & 0x03) + 1;

    if (pn_offset + pn_len + 16 > (size_t)pkt_len) return 0;

    uint64_t pn = 0;
    for (uint8_t i = 0; i < pn_len; i++)
        pn = (pn << 8) | (pkt[pn_offset + i] ^ mask[i + 1]);

    uint8_t nonce[12];
    memcpy(nonce, iv, 12);
    uint64_t pn_tmp = pn;
    for (int i = 11; i >= 0; i--) {
        nonce[i] ^= (uint8_t)(pn_tmp & 0xFF);
        pn_tmp >>= 8;
    }

    const uint8_t *ct = pkt + pn_offset + pn_len;
    size_t ct_len = (size_t)payload_len - pn_len;
    if (ct_len < 16) return 0;
    size_t plain_len = ct_len - 16;

    static uint8_t plain[2048];
    if (plain_len > sizeof(plain)) plain_len = sizeof(plain);

    aes128_ctr_xor(key, nonce, 2, ct, plain, plain_len);

    size_t fpos = 0;
    while (fpos < plain_len) {
        uint64_t ftype;
        if (!read_varint(plain, plain_len, &fpos, &ftype)) break;

        if (ftype == 0x00) {
            continue;
        }
        if (ftype == 0x01) {
            continue;
        }
        if (ftype == 0x02 || ftype == 0x03) {
            uint64_t v, range_count;
            if (!read_varint(plain, plain_len, &fpos, &v)) break;
            if (!read_varint(plain, plain_len, &fpos, &v)) break;
            if (!read_varint(plain, plain_len, &fpos, &range_count)) break;
            if (!read_varint(plain, plain_len, &fpos, &v)) break;
            for (uint64_t i = 0; i < range_count; i++) {
                if (!read_varint(plain, plain_len, &fpos, &v)) goto done;
                if (!read_varint(plain, plain_len, &fpos, &v)) goto done;
            }
            if (ftype == 0x03) {
                for (int i = 0; i < 3; i++)
                    if (!read_varint(plain, plain_len, &fpos, &v)) goto done;
            }
            continue;
        }
        if (ftype == 0x06) {
            uint64_t offset, length;
            if (!read_varint(plain, plain_len, &fpos, &offset)) break;
            if (!read_varint(plain, plain_len, &fpos, &length)) break;
            if (fpos + (size_t)length > plain_len) break;

            if (frag && !frag->found) {
                frag->found  = 1;
                frag->offset = offset;
                frag->data   = plain + fpos;
                frag->len    = (size_t)length;
            }

            if (offset == 0 &&
                quic_ch_to_sni(plain + fpos, (size_t)length, host, host_size))
                return 1;

            fpos += (size_t)length;
            continue;
        }
        break;
    }

done:
    return 0;
}
