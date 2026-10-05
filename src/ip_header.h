#ifndef IP_HEADER_H
#define IP_HEADER_H

#include <stdint.h>

/*
 * Estructura del header IPv4 (RFC 791), 20 bytes sin opciones.
 * Tomada del Laboratorio #05. #pragma pack evita que el compilador
 * inserte padding entre campos.
 */
#pragma pack(push, 1)
typedef struct {
    uint8_t  ihl_version;   /* 4 bits version + 4 bits IHL (longitud en palabras de 32 bits) */
    uint8_t  tos;           /* Type of Service */
    uint16_t total_length;  /* Longitud total del paquete IP (header + datos) */
    uint16_t id;            /* Identificador del paquete, usado en fragmentación */
    uint16_t flags_fo;      /* 3 bits flags + 13 bits fragment offset */
    uint8_t  ttl;           /* Time To Live: el campo clave de traceroute */
    uint8_t  protocol;      /* Protocolo encapsulado (17 = UDP) */
    uint16_t checksum;      /* Checksum del header IP */
    uint32_t src_addr;      /* IP origen, en orden de red */
    uint32_t dst_addr;      /* IP destino, en orden de red */
} ip_header_t;
#pragma pack(pop)

#define IP_HEADER_LEN 20

/*
 * Llena iph con un header IPv4 y calcula su checksum.
 * src_addr y dst_addr van en orden de red.
 * payload_len = longitud de todo lo que va DESPUÉS del header IP.
 */
void build_ip_header(ip_header_t *iph, uint32_t src_addr, uint32_t dst_addr,
                     uint16_t payload_len, uint8_t ttl, uint8_t protocol,
                     uint16_t id);

#endif /* IP_HEADER_H */
