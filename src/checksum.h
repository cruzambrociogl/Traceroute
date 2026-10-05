#ifndef CHECKSUM_H
#define CHECKSUM_H

#include <stdint.h>
#include <stddef.h>

/*
 * Internet checksum (RFC 1071): complemento a uno de la suma en complemento
 * a uno de todas las palabras de 16 bits del buffer.
 * Se usa para el header IP y (con el pseudo-header) para UDP.
 * El resultado ya está listo para copiarse tal cual al campo del header.
 */
uint16_t calculate_checksum(const void *buffer, size_t size);

/*
 * Checksum UDP: igual que el anterior, pero calculado sobre
 * pseudo-header (IP origen, IP destino, 0, protocolo, longitud UDP)
 * + header UDP + datos.  src_addr y dst_addr van en orden de red.
 * Si el resultado da 0 se devuelve 0xFFFF, porque en UDP un 0 significa
 * "sin checksum" (RFC 768).
 */
uint16_t calculate_udp_checksum(uint32_t src_addr, uint32_t dst_addr,
                                const uint8_t *udp_segment, size_t udp_segment_len);

#endif /* CHECKSUM_H */
