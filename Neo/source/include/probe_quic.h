#ifndef PROBE_QUIC_H
#define PROBE_QUIC_H

#include <stdint.h>
#include <stddef.h>

typedef struct {
    int      found;
    uint64_t offset;
    const uint8_t *data;
    size_t   len;
} quic_crypto_frag_t;

int quic_extract_sni(const uint8_t *quic_pkt, int pkt_len,
                     char *host, size_t host_size,
                     quic_crypto_frag_t *frag);

int quic_ch_to_sni(const uint8_t *ch, size_t ch_len,
                   char *host, size_t host_size);

#endif
