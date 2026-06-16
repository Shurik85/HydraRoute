#include "../include/quic_crypto.h"
#include <string.h>

#define ROTR32(x, n) (((x) >> (n)) | ((x) << (32 - (n))))
#define CH(e,f,g)    (((e) & (f)) ^ (~(e) & (g)))
#define MAJ(a,b,c)   (((a) & (b)) ^ ((a) & (c)) ^ ((b) & (c)))
#define EP0(x)       (ROTR32(x,2)  ^ ROTR32(x,13) ^ ROTR32(x,22))
#define EP1(x)       (ROTR32(x,6)  ^ ROTR32(x,11) ^ ROTR32(x,25))
#define SIG0(x)      (ROTR32(x,7)  ^ ROTR32(x,18) ^ ((x) >> 3))
#define SIG1(x)      (ROTR32(x,17) ^ ROTR32(x,19) ^ ((x) >> 10))

static const uint32_t K256[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

typedef struct {
    uint32_t state[8];
    uint64_t count;
    uint8_t  buf[64];
    uint32_t buf_len;
} sha256_ctx;

static void sha256_compress(uint32_t st[8], const uint8_t blk[64]) {
    uint32_t w[64];
    for (int i = 0; i < 16; i++)
        w[i] = ((uint32_t)blk[i*4]   << 24) | ((uint32_t)blk[i*4+1] << 16) |
               ((uint32_t)blk[i*4+2] <<  8) |  (uint32_t)blk[i*4+3];
    for (int i = 16; i < 64; i++)
        w[i] = SIG1(w[i-2]) + w[i-7] + SIG0(w[i-15]) + w[i-16];

    uint32_t a=st[0],b=st[1],c=st[2],d=st[3],e=st[4],f=st[5],g=st[6],h=st[7];
    for (int i = 0; i < 64; i++) {
        uint32_t t1 = h + EP1(e) + CH(e,f,g) + K256[i] + w[i];
        uint32_t t2 = EP0(a) + MAJ(a,b,c);
        h=g; g=f; f=e; e=d+t1; d=c; c=b; b=a; a=t1+t2;
    }
    st[0]+=a; st[1]+=b; st[2]+=c; st[3]+=d;
    st[4]+=e; st[5]+=f; st[6]+=g; st[7]+=h;
}

static void sha256_init(sha256_ctx *c) {
    c->state[0]=0x6a09e667; c->state[1]=0xbb67ae85;
    c->state[2]=0x3c6ef372; c->state[3]=0xa54ff53a;
    c->state[4]=0x510e527f; c->state[5]=0x9b05688c;
    c->state[6]=0x1f83d9ab; c->state[7]=0x5be0cd19;
    c->count = 0;
    c->buf_len = 0;
}

static void sha256_update(sha256_ctx *c, const uint8_t *data, size_t len) {
    while (len > 0) {
        size_t copy = 64 - c->buf_len;
        if (copy > len) copy = len;
        memcpy(c->buf + c->buf_len, data, copy);
        c->buf_len += (uint32_t)copy;
        c->count   += copy;
        data += copy;
        len  -= copy;
        if (c->buf_len == 64) {
            sha256_compress(c->state, c->buf);
            c->buf_len = 0;
        }
    }
}

static void sha256_final(sha256_ctx *c, uint8_t out[32]) {
    uint64_t bits = c->count * 8;
    c->buf[c->buf_len++] = 0x80;
    if (c->buf_len > 56) {
        memset(c->buf + c->buf_len, 0, 64 - c->buf_len);
        sha256_compress(c->state, c->buf);
        c->buf_len = 0;
    }
    memset(c->buf + c->buf_len, 0, 56 - c->buf_len);
    c->buf[56] = (uint8_t)(bits >> 56); c->buf[57] = (uint8_t)(bits >> 48);
    c->buf[58] = (uint8_t)(bits >> 40); c->buf[59] = (uint8_t)(bits >> 32);
    c->buf[60] = (uint8_t)(bits >> 24); c->buf[61] = (uint8_t)(bits >> 16);
    c->buf[62] = (uint8_t)(bits >>  8); c->buf[63] = (uint8_t)(bits);
    sha256_compress(c->state, c->buf);
    for (int i = 0; i < 8; i++) {
        out[i*4]   = (uint8_t)(c->state[i] >> 24);
        out[i*4+1] = (uint8_t)(c->state[i] >> 16);
        out[i*4+2] = (uint8_t)(c->state[i] >>  8);
        out[i*4+3] = (uint8_t)(c->state[i]);
    }
}

void sha256(const uint8_t *data, size_t len, uint8_t out[32]) {
    sha256_ctx c;
    sha256_init(&c);
    sha256_update(&c, data, len);
    sha256_final(&c, out);
}

void hmac_sha256(const uint8_t *key, size_t klen,
                 const uint8_t *data, size_t dlen, uint8_t out[32]) {
    uint8_t k[64];
    memset(k, 0, 64);
    if (klen > 64) sha256(key, klen, k);
    else           memcpy(k, key, klen);

    uint8_t ipad[64], opad[64];
    for (int i = 0; i < 64; i++) {
        ipad[i] = k[i] ^ 0x36;
        opad[i] = k[i] ^ 0x5c;
    }

    uint8_t inner[32];
    sha256_ctx c;
    sha256_init(&c);
    sha256_update(&c, ipad, 64);
    sha256_update(&c, data, dlen);
    sha256_final(&c, inner);

    sha256_init(&c);
    sha256_update(&c, opad, 64);
    sha256_update(&c, inner, 32);
    sha256_final(&c, out);
}

void hkdf_extract(const uint8_t *salt, size_t salt_len,
                  const uint8_t *ikm, size_t ikm_len, uint8_t out[32]) {
    hmac_sha256(salt, salt_len, ikm, ikm_len, out);
}

void hkdf_expand_label(const uint8_t prk[32], const char *label,
                       uint8_t *out, size_t out_len) {
    const char prefix[] = "tls13 ";
    size_t label_len = 0;
    while (label[label_len]) label_len++;
    size_t full_len = 6 + label_len;

    uint8_t info[64];
    size_t pos = 0;
    info[pos++] = (uint8_t)(out_len >> 8);
    info[pos++] = (uint8_t)(out_len);
    info[pos++] = (uint8_t)(full_len);
    memcpy(info + pos, prefix, 6); pos += 6;
    memcpy(info + pos, label, label_len); pos += label_len;
    info[pos++] = 0x00;
    info[pos++] = 0x01;

    uint8_t t1[32];
    hmac_sha256(prk, 32, info, pos, t1);
    memcpy(out, t1, out_len);
}

static const uint8_t AES_SBOX[256] = {
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
};

static const uint8_t RCON[10] = {0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36};

static uint8_t xtime(uint8_t x) {
    return (uint8_t)((x << 1) ^ ((x & 0x80) ? 0x1b : 0x00));
}

static void aes_key_schedule(const uint8_t key[16], uint8_t rk[11][16]) {
    uint8_t w[44][4];
    for (int i = 0; i < 4; i++) memcpy(w[i], key + 4*i, 4);
    for (int i = 4; i < 44; i++) {
        uint8_t t[4];
        memcpy(t, w[i-1], 4);
        if (i % 4 == 0) {
            uint8_t tmp = t[0]; t[0]=t[1]; t[1]=t[2]; t[2]=t[3]; t[3]=tmp;
            for (int j = 0; j < 4; j++) t[j] = AES_SBOX[t[j]];
            t[0] ^= RCON[i/4 - 1];
        }
        for (int j = 0; j < 4; j++) w[i][j] = w[i-4][j] ^ t[j];
    }
    for (int r = 0; r <= 10; r++)
        for (int c = 0; c < 4; c++)
            memcpy(rk[r] + 4*c, w[r*4 + c], 4);
}

static void aes_encrypt_block(const uint8_t rk[11][16], const uint8_t in[16], uint8_t out[16]) {
    uint8_t s[16];
    memcpy(s, in, 16);
    for (int i = 0; i < 16; i++) s[i] ^= rk[0][i];

    for (int rnd = 1; rnd <= 10; rnd++) {
        for (int i = 0; i < 16; i++) s[i] = AES_SBOX[s[i]];

        uint8_t t;
        t=s[1]; s[1]=s[5]; s[5]=s[9];  s[9]=s[13]; s[13]=t;
        t=s[2]; s[2]=s[10]; s[10]=t;   t=s[6]; s[6]=s[14]; s[14]=t;
        t=s[15];s[15]=s[11];s[11]=s[7];s[7]=s[3]; s[3]=t;

        if (rnd < 10) {
            for (int c = 0; c < 4; c++) {
                uint8_t a=s[c*4],b=s[c*4+1],cc=s[c*4+2],d=s[c*4+3];
                uint8_t a2=xtime(a),b2=xtime(b),c2=xtime(cc),d2=xtime(d);
                s[c*4]   = a2 ^ (b2^b) ^ cc ^ d;
                s[c*4+1] = a  ^ b2     ^ (c2^cc) ^ d;
                s[c*4+2] = a  ^ b      ^ c2 ^ (d2^d);
                s[c*4+3] = (a2^a) ^ b  ^ cc ^ d2;
            }
        }

        for (int i = 0; i < 16; i++) s[i] ^= rk[rnd][i];
    }
    memcpy(out, s, 16);
}

void aes128_ecb_encrypt(const uint8_t key[16], const uint8_t in[16], uint8_t out[16]) {
    uint8_t rk[11][16];
    aes_key_schedule(key, rk);
    aes_encrypt_block(rk, in, out);
}

void aes128_ctr_xor(const uint8_t key[16], const uint8_t nonce[12], uint32_t ctr_start,
                    const uint8_t *in, uint8_t *out, size_t len) {
    uint8_t rk[11][16];
    aes_key_schedule(key, rk);

    uint8_t ctr[16];
    memcpy(ctr, nonce, 12);
    ctr[12] = (uint8_t)(ctr_start >> 24);
    ctr[13] = (uint8_t)(ctr_start >> 16);
    ctr[14] = (uint8_t)(ctr_start >>  8);
    ctr[15] = (uint8_t)(ctr_start);

    uint8_t ks[16];
    size_t pos = 0;
    while (pos < len) {
        aes_encrypt_block(rk, ctr, ks);
        size_t blen = (len - pos > 16) ? 16 : (len - pos);
        for (size_t i = 0; i < blen; i++) out[pos + i] = in[pos + i] ^ ks[i];
        pos += blen;
        for (int i = 15; i >= 12; i--) if (++ctr[i]) break;
    }
}
