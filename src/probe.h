#ifndef PROBE_H
#define PROBE_H

#include <stdint.h>
#include <stddef.h>

#include "ip_header.h"
#include "udp_header.h"

/*
 * Un probe es un datagrama IP + UDP armado a mano:
 *
 *   | header IP (20) | header UDP (8) | datos (32) |  = 60 bytes
 *
 * Mismo tamaño que el traceroute de Linux ("60 byte packets").
 */
#define PROBE_DATA_LEN   32
#define PROBE_PACKET_LEN (IP_HEADER_LEN + UDP_HEADER_LEN + PROBE_DATA_LEN)

/*
 * Arma el probe en 'packet' (al menos PROBE_PACKET_LEN bytes).
 * src_addr/dst_addr en orden de red; puertos e id en orden del host.
 * El TTL es lo único que cambia de un salto a otro.
 * Retorna la longitud total del paquete.
 */
size_t build_probe(uint8_t *packet, uint32_t src_addr, uint32_t dst_addr,
                   uint16_t src_port, uint16_t dst_port, uint8_t ttl, uint16_t ip_id);

#endif /* PROBE_H */
