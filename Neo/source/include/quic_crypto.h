#ifndef QUIC_CRYPTO_H
#define QUIC_CRYPTO_H

#include <stdint.h>
#include <stddef.h>

void sha256(const uint8_t *data, size_t len, uint8_t out[32]);
void hmac_sha256(const uint8_t *key, size_t klen,
                 const uint8_t *data, size_t dlen, uint8_t out[32]);
void hkdf_extract(const uint8_t *salt, size_t salt_len,
                  const uint8_t *ikm, size_t ikm_len, uint8_t out[32]);
void hkdf_expand_label(const uint8_t prk[32], const char *label,
                       uint8_t *out, size_t out_len);
void aes128_ecb_encrypt(const uint8_t key[16], const uint8_t in[16], uint8_t out[16]);
void aes128_ctr_xor(const uint8_t key[16], const uint8_t nonce[12], uint32_t ctr_start,
                    const uint8_t *in, uint8_t *out, size_t len);

#endif
