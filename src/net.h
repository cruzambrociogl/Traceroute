#ifndef NET_H
#define NET_H

#include <stdint.h>
#include <stddef.h>

/*
 * Socket de ENVÍO: raw socket IPPROTO_RAW con IP_HDRINCL, para que el
 * header IP (y sobre todo el TTL) lo armemos nosotros. Requiere root.
 */
int open_send_socket(void);

/*
 * Socket de RECEPCIÓN: raw socket IPPROTO_ICMP. El kernel le entrega una
 * copia de cada ICMP que llega (con su header IP), tanto en Linux como en
 * macOS, así que aquí no hace falta libpcap como en el Laboratorio #05.
 */
int open_recv_socket(void);

/* Envía el paquete ya armado hacia dst_addr (orden de red). */
int send_probe(int sockfd, const uint8_t *packet, size_t len, uint32_t dst_addr);

/* Resuelve un nombre o IP a una dirección IPv4 (orden de red). 0 = ok. */
int resolve_target(const char *host, uint32_t *addr);

/*
 * Averigua qué IP local usaría el kernel para llegar a dst_addr.
 * Truco: connect() de un socket UDP no envía nada, sólo consulta la tabla
 * de rutas; luego getsockname() nos dice la IP origen elegida.
 */
int get_source_addr(uint32_t dst_addr, uint32_t *src_addr);

/*
 * Escribe "nombre (ip)" en buf. Si numeric != 0 o no hay DNS inverso,
 * el nombre es la misma IP, igual que el traceroute del sistema.
 */
void format_hop_addr(uint32_t addr, int numeric, char *buf, size_t buflen);

#endif /* NET_H */
