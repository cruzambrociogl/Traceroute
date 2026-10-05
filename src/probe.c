#include "probe.h"
#include "checksum.h"

#include <string.h>
#include <netinet/in.h>

size_t build_probe(uint8_t *packet, uint32_t src_addr, uint32_t dst_addr,
                   uint16_t src_port, uint16_t dst_port, uint8_t ttl, uint16_t ip_id) {
    ip_header_t  *iph  = (ip_header_t *)packet;
    udp_header_t *udph = (udp_header_t *)(packet + IP_HEADER_LEN);
    uint8_t      *data = packet + IP_HEADER_LEN + UDP_HEADER_LEN;

    /* Datos de relleno: "@ABCDEF...", el mismo patrón que usa traceroute en Linux */
    for (int i = 0; i < PROBE_DATA_LEN; i++) {
        data[i] = (uint8_t)(0x40 + i);
    }

    /* 1) UDP: el puerto destino identifica a cada probe (33434, 33435, ...) */
    build_udp_header(udph, src_port, dst_port, PROBE_DATA_LEN);
    udph->checksum = calculate_udp_checksum(src_addr, dst_addr, (uint8_t *)udph,
                                            UDP_HEADER_LEN + PROBE_DATA_LEN);

    /* 2) IP: aquí va el TTL que hace que el router N descarte el paquete */
    build_ip_header(iph, src_addr, dst_addr, UDP_HEADER_LEN + PROBE_DATA_LEN,
                    ttl, IPPROTO_UDP, ip_id);

    return PROBE_PACKET_LEN;
}
