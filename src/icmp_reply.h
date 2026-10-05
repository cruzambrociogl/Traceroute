#ifndef ICMP_REPLY_H
#define ICMP_REPLY_H

#include <stdint.h>
#include <stddef.h>

/* Tipos ICMP que nos interesan (RFC 792) */
#define ICMP_TYPE_DEST_UNREACH  3   /* el destino (o un router) no puede entregar */
#define ICMP_TYPE_TIME_EXCEEDED 11  /* un router descartó el paquete porque TTL llegó a 0 */

/* Códigos de Destination Unreachable */
#define ICMP_CODE_NET_UNREACH   0   /* !N */
#define ICMP_CODE_HOST_UNREACH  1   /* !H */
#define ICMP_CODE_PROTO_UNREACH 2   /* !P */
#define ICMP_CODE_PORT_UNREACH  3   /* llegamos al destino: nadie escucha en ese puerto UDP */
#define ICMP_CODE_ADMIN_PROHIB  13  /* !X */

/*
 * Lo que extraemos de una respuesta ICMP. Un mensaje de error ICMP trae
 * adentro una copia del header IP original + los primeros 8 bytes de lo
 * que iba encima (nuestro header UDP completo). Con eso sabemos a qué
 * probe corresponde la respuesta.
 *
 *   | IP externo | ICMP (8) | IP original (nuestro probe) | UDP original (8) |
 */
typedef struct {
    uint32_t from;         /* quién respondió (IP origen del header externo), orden de red */
    uint8_t  type;
    uint8_t  code;
    uint32_t inner_dst;    /* destino del probe original, orden de red */
    uint16_t inner_sport;  /* puertos UDP del probe original, orden del host */
    uint16_t inner_dport;
} icmp_reply_t;

/*
 * Interpreta un paquete recibido en el raw socket ICMP (empieza con el
 * header IP). Retorna 0 si es un Time Exceeded / Dest Unreachable que
 * contiene un probe UDP, -1 si no nos interesa (ping de otro programa,
 * paquete truncado, etc.).
 */
int parse_icmp_reply(const uint8_t *buffer, size_t len, icmp_reply_t *out);

#endif /* ICMP_REPLY_H */
