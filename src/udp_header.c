#include "udp_header.h"

#include <string.h>
#include <arpa/inet.h>

_Static_assert(sizeof(udp_header_t) == UDP_HEADER_LEN, "udp_header_t debe medir 8 bytes");

void build_udp_header(udp_header_t *udph, uint16_t src_port, uint16_t dst_port,
                      uint16_t payload_len) {
    memset(udph, 0, sizeof(*udph));
    udph->src_port = htons(src_port);
    udph->dst_port = htons(dst_port);
    udph->length   = htons((uint16_t)(UDP_HEADER_LEN + payload_len));
    udph->checksum = 0;
}
