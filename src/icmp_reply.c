#include "icmp_reply.h"

#include <string.h>
#include <netinet/in.h>

#define ICMP_HEADER_LEN 8   /* type, code, checksum, 4 bytes "unused" */

int parse_icmp_reply(const uint8_t *buffer, size_t len, icmp_reply_t *out) {
    /* --- header IP externo (el que puso el router que respondió) --- */
    if (len < 20) return -1;
    size_t outer_ihl = (size_t)(buffer[0] & 0x0F) * 4;
    if (outer_ihl < 20 || len < outer_ihl + ICMP_HEADER_LEN) return -1;

    /* --- header ICMP --- */
    const uint8_t *icmp = buffer + outer_ihl;
    uint8_t type = icmp[0];
    uint8_t code = icmp[1];
    if (type != ICMP_TYPE_TIME_EXCEEDED && type != ICMP_TYPE_DEST_UNREACH) return -1;

    /* --- copia de NUESTRO header IP, dentro del mensaje ICMP --- */
    const uint8_t *inner = icmp + ICMP_HEADER_LEN;
    size_t inner_avail = len - outer_ihl - ICMP_HEADER_LEN;
    if (inner_avail < 20) return -1;
    size_t inner_ihl = (size_t)(inner[0] & 0x0F) * 4;
    if (inner_ihl < 20 || inner_avail < inner_ihl + 8) return -1;
    if (inner[9] != IPPROTO_UDP) return -1;   /* byte 9 = campo protocol */

    /* --- primeros 8 bytes de NUESTRO header UDP --- */
    const uint8_t *inner_udp = inner + inner_ihl;

    memcpy(&out->from, buffer + 12, 4);       /* bytes 12..15 = IP origen */
    memcpy(&out->inner_dst, inner + 16, 4);   /* bytes 16..19 = IP destino */
    out->type        = type;
    out->code        = code;
    out->inner_sport = (uint16_t)((inner_udp[0] << 8) | inner_udp[1]);
    out->inner_dport = (uint16_t)((inner_udp[2] << 8) | inner_udp[3]);
    return 0;
}
