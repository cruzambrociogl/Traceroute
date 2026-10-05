#include "ip_header.h"
#include "checksum.h"

#include <string.h>
#include <arpa/inet.h>

_Static_assert(sizeof(ip_header_t) == IP_HEADER_LEN, "ip_header_t debe medir 20 bytes");

void build_ip_header(ip_header_t *iph, uint32_t src_addr, uint32_t dst_addr,
                     uint16_t payload_len, uint8_t ttl, uint8_t protocol,
                     uint16_t id) {
    memset(iph, 0, sizeof(*iph));

    iph->ihl_version = (4 << 4) | 5;    /* Version 4, IHL 5 -> 5*4 = 20 bytes */
    iph->tos         = 0;

#if defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__)
    /*
     * Particularidad de BSD/macOS (igual que en el Laboratorio #05): con
     * IP_HDRINCL el kernel espera ip_len e ip_off en BYTE ORDER DEL HOST.
     * Con htons() aquí, sendto() falla con EINVAL.
     */
    iph->total_length = (uint16_t)(IP_HEADER_LEN + payload_len);
    iph->flags_fo     = 0;          /* sin DF: igual que el traceroute clásico */
#else
    iph->total_length = htons((uint16_t)(IP_HEADER_LEN + payload_len));
    iph->flags_fo     = htons(0);
#endif

    iph->id       = htons(id);
    iph->ttl      = ttl;
    iph->protocol = protocol;
    iph->src_addr = src_addr;
    iph->dst_addr = dst_addr;

    /*
     * Calculamos el checksum nosotros. Tanto Linux como macOS lo vuelven a
     * calcular al enviar con IP_HDRINCL, pero así el paquete queda completo
     * y correcto tal como lo armamos.
     */
    iph->checksum = 0;
    iph->checksum = calculate_checksum(iph, IP_HEADER_LEN);
}
