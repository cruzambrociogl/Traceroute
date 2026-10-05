#ifndef UDP_HEADER_H
#define UDP_HEADER_H

#include <stdint.h>

/* Header UDP (RFC 768), 8 bytes. Todos los campos en orden de red. */
#pragma pack(push, 1)
typedef struct {
    uint16_t src_port;
    uint16_t dst_port;
    uint16_t length;    /* header UDP + datos */
    uint16_t checksum;  /* se calcula aparte con calculate_udp_checksum() */
} udp_header_t;
#pragma pack(pop)

#define UDP_HEADER_LEN 8

/*
 * Llena udph. payload_len = bytes de datos después del header UDP.
 * El checksum queda en 0: se calcula cuando los datos ya están copiados.
 */
void build_udp_header(udp_header_t *udph, uint16_t src_port, uint16_t dst_port,
                      uint16_t payload_len);

#endif /* UDP_HEADER_H */
