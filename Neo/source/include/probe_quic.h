#ifndef PROBE_QUIC_H
#define PROBE_QUIC_H

#include <stdint.h>
#include <stddef.h>

int quic_extract_sni(const uint8_t *quic_pkt, int pkt_len,
                     char *host, size_t host_size);

#endif
