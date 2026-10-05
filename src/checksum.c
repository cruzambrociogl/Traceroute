#include "checksum.h"

#include <string.h>
#include <netinet/in.h>

/* Pseudo-header UDP: sólo se usa para calcular el checksum, nunca se envía */
#pragma pack(push, 1)
typedef struct {
    uint32_t src_addr;
    uint32_t dst_addr;
    uint8_t  zero;
    uint8_t  protocol;
    uint16_t udp_length;
} pseudo_header_t;
#pragma pack(pop)

/* Suma (sin complementar) que se puede ir acumulando sobre varios buffers */
static uint32_t checksum_add(uint32_t sum, const void *buffer, size_t size) {
    const uint8_t *p = buffer;

    while (size > 1) {
        uint16_t word;
        memcpy(&word, p, 2);   /* memcpy evita lecturas desalineadas */
        sum += word;
        p += 2;
        size -= 2;
    }
    if (size == 1) {
        uint16_t word = 0;
        memcpy(&word, p, 1);   /* último byte impar, rellenado con un 0 */
        sum += word;
    }
    return sum;
}

static uint16_t checksum_fold(uint32_t sum) {
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    return (uint16_t)(~sum);
}

uint16_t calculate_checksum(const void *buffer, size_t size) {
    return checksum_fold(checksum_add(0, buffer, size));
}

uint16_t calculate_udp_checksum(uint32_t src_addr, uint32_t dst_addr,
                                const uint8_t *udp_segment, size_t udp_segment_len) {
    pseudo_header_t psh;
    psh.src_addr   = src_addr;
    psh.dst_addr   = dst_addr;
    psh.zero       = 0;
    psh.protocol   = IPPROTO_UDP;
    psh.udp_length = htons((uint16_t)udp_segment_len);

    uint32_t sum = checksum_add(0, &psh, sizeof(psh));
    sum = checksum_add(sum, udp_segment, udp_segment_len);

    uint16_t result = checksum_fold(sum);
    return result == 0 ? 0xFFFF : result;
}
