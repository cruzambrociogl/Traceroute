#include "net.h"

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <netdb.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

int open_send_socket(void) {
    int sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (sockfd < 0) {
        perror("[net] Error creando el raw socket de envio (¿estas corriendo con sudo?)");
        return -1;
    }

    /* IPPROTO_RAW ya implica IP_HDRINCL, pero lo dejamos explícito */
    int one = 1;
    if (setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0) {
        perror("[net] Error en setsockopt(IP_HDRINCL)");
        close(sockfd);
        return -1;
    }
    return sockfd;
}

int open_recv_socket(void) {
    int sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (sockfd < 0) {
        perror("[net] Error creando el raw socket ICMP (¿estas corriendo con sudo?)");
        return -1;
    }
    return sockfd;
}

int send_probe(int sockfd, const uint8_t *packet, size_t len, uint32_t dst_addr) {
    struct sockaddr_in dest;
    memset(&dest, 0, sizeof(dest));
    dest.sin_family      = AF_INET;
    dest.sin_addr.s_addr = dst_addr;

    ssize_t sent = sendto(sockfd, packet, len, 0, (struct sockaddr *)&dest, sizeof(dest));
    if (sent < 0) {
        perror("[net] Error en sendto");
        return -1;
    }
    return (int)sent;
}

int resolve_target(const char *host, uint32_t *addr) {
    struct addrinfo hints, *res;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;   /* sólo IPv4: nuestro header es IPv4 */

    int rc = getaddrinfo(host, NULL, &hints, &res);
    if (rc != 0) {
        fprintf(stderr, "%s: %s\n", host, gai_strerror(rc));
        return -1;
    }
    *addr = ((struct sockaddr_in *)res->ai_addr)->sin_addr.s_addr;
    freeaddrinfo(res);
    return 0;
}

int get_source_addr(uint32_t dst_addr, uint32_t *src_addr) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        perror("[net] socket(SOCK_DGRAM)");
        return -1;
    }

    struct sockaddr_in dest;
    memset(&dest, 0, sizeof(dest));
    dest.sin_family      = AF_INET;
    dest.sin_addr.s_addr = dst_addr;
    dest.sin_port        = htons(33434);

    if (connect(fd, (struct sockaddr *)&dest, sizeof(dest)) < 0) {
        perror("[net] No hay ruta hacia el destino");
        close(fd);
        return -1;
    }

    struct sockaddr_in local;
    socklen_t local_len = sizeof(local);
    if (getsockname(fd, (struct sockaddr *)&local, &local_len) < 0) {
        perror("[net] getsockname");
        close(fd);
        return -1;
    }
    close(fd);
    *src_addr = local.sin_addr.s_addr;
    return 0;
}

void lookup_hop_name(uint32_t addr, char *name, size_t namelen) {
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family      = AF_INET;
    sa.sin_addr.s_addr = addr;

    if (getnameinfo((struct sockaddr *)&sa, sizeof(sa), name, (socklen_t)namelen,
                    NULL, 0, NI_NAMEREQD) != 0) {
        inet_ntop(AF_INET, &sa.sin_addr, name, (socklen_t)namelen);
    }
}
