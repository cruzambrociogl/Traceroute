/*
 * Pruebas sin root: arma un probe, verifica sus checksums y simula la
 * respuesta ICMP de un router para comprobar que el parser la reconoce.
 */
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>

#include "../src/checksum.h"
#include "../src/probe.h"
#include "../src/icmp_reply.h"

static int failures = 0;

#define CHECK(cond, msg) do { \
    if (cond) printf("  ok   %s\n", msg); \
    else { printf("  FAIL %s\n", msg); failures++; } \
} while (0)

/* Arma "IP externo + ICMP(type, code) + primeros 28 bytes del probe" */
static size_t fake_icmp(uint8_t *out, uint32_t router, uint32_t me,
                        uint8_t type, uint8_t code, const uint8_t *probe) {
    memset(out, 0, 20 + 8 + 28);
    out[0] = 0x45;                    /* IPv4, IHL 5 */
    out[8] = 250;                     /* TTL del router */
    out[9] = 1;                       /* protocol = ICMP */
    memcpy(out + 12, &router, 4);
    memcpy(out + 16, &me, 4);
    out[20] = type;
    out[21] = code;
    memcpy(out + 28, probe, 28);      /* header IP + UDP de nuestro probe */
    return 20 + 8 + 28;
}

int main(void) {
    uint32_t src    = inet_addr("192.168.1.10");
    uint32_t dst    = inet_addr("216.239.32.21");
    uint32_t router = inet_addr("10.135.128.1");
    uint8_t probe[PROBE_PACKET_LEN];

    printf("probe:\n");
    size_t len = build_probe(probe, src, dst, 40000, 33437, 5, 7);
    CHECK(len == 60, "mide 60 bytes (20 IP + 8 UDP + 32 datos)");
    CHECK(probe[0] == 0x45, "version 4, IHL 5");
    CHECK(probe[8] == 5, "TTL = 5 en el byte 8");
    CHECK(probe[9] == 17, "protocol = 17 (UDP)");
    CHECK(calculate_checksum(probe, 20) == 0, "checksum IP valido (la suma da 0)");
    CHECK(probe[22] == 0x82 && probe[23] == 0x9D, "puerto destino 33437 en orden de red");

    /* Verificación del checksum UDP: recalcularlo con el campo incluido debe dar 0 */
    uint8_t udp_copy[8 + PROBE_DATA_LEN];
    memcpy(udp_copy, probe + 20, sizeof(udp_copy));
    uint16_t stored;
    memcpy(&stored, udp_copy + 6, 2);
    memset(udp_copy + 6, 0, 2);
    CHECK(calculate_udp_checksum(src, dst, udp_copy, sizeof(udp_copy)) == stored,
          "checksum UDP coincide al recalcularlo");

    printf("respuesta ICMP Time Exceeded:\n");
    uint8_t reply_buf[128];
    icmp_reply_t r;
    size_t rlen = fake_icmp(reply_buf, router, src, 11, 0, probe);
    CHECK(parse_icmp_reply(reply_buf, rlen, &r) == 0, "se reconoce");
    CHECK(r.from == router, "IP del router que respondio");
    CHECK(r.inner_dst == dst, "destino original recuperado");
    CHECK(r.inner_sport == 40000 && r.inner_dport == 33437, "puertos originales recuperados");

    printf("respuesta ICMP Port Unreachable del destino:\n");
    rlen = fake_icmp(reply_buf, dst, src, 3, 3, probe);
    CHECK(parse_icmp_reply(reply_buf, rlen, &r) == 0 && r.type == 3 && r.code == 3,
          "tipo 3 codigo 3");

    printf("paquetes que se deben ignorar:\n");
    rlen = fake_icmp(reply_buf, router, src, 0, 0, probe);   /* echo reply */
    CHECK(parse_icmp_reply(reply_buf, rlen, &r) != 0, "echo reply (ping de otro programa)");
    CHECK(parse_icmp_reply(reply_buf, 30, &r) != 0, "paquete truncado");

    printf(failures ? "\n%d prueba(s) fallaron\n" : "\ntodas las pruebas pasaron\n", failures);
    return failures ? 1 : 0;
}
