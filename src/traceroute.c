/*
 * mytraceroute: traceroute básico con RAW sockets.
 *
 * Por cada TTL (1, 2, 3, ...) se envían N probes UDP armados a mano.
 * El router donde el TTL llega a 0 responde ICMP Time Exceeded (tipo 11);
 * cuando el probe llega al destino, éste responde ICMP Port Unreachable
 * (tipo 3, código 3) porque nadie escucha en el puerto 33434+n. Ahí termina.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <errno.h>
#include <time.h>
#include <poll.h>
#include <unistd.h>
#include <getopt.h>
#include <netdb.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#include "net.h"
#include "probe.h"
#include "icmp_reply.h"

#define DEFAULT_FIRST_TTL  1
#define DEFAULT_MAX_HOPS   64
#define DEFAULT_PROBES     3
#define DEFAULT_WAIT_SEC   3.0
#define DEFAULT_PAUSE_MS   100
#define DEFAULT_BASE_PORT  33434

typedef struct {
    int      first_ttl;
    int      max_hops;
    int      probes;
    double   wait_sec;
    int      pause_ms;
    int      base_port;
    int      numeric;    /* -n: no hacer DNS inverso */
    int      verbose;    /* -v: mostrar cada probe y cada respuesta */
    int      color;      /* -c: forzar colores aunque la salida no sea una terminal */
    const char *host;
} options_t;

typedef struct {
    int      send_fd;
    int      recv_fd;
    uint32_t src_addr;   /* orden de red */
    uint32_t dst_addr;   /* orden de red */
    uint16_t src_port;   /* identifica a ESTA ejecución entre otros traceroutes */
} trace_ctx_t;

/* ------------------------------------------------------------------ */
/* Colores ANSI (los mismos que usa el enunciado para cada campo)      */
/* ------------------------------------------------------------------ */

typedef struct {
    const char *hop;     /* número de salto: verde */
    const char *name;    /* nombre DNS: cian */
    const char *ip;      /* dirección IP: rojo */
    const char *time;    /* tiempos: amarillo */
    const char *star;    /* asterisco: magenta */
    const char *note;    /* !H, !N, ...: rojo en negrita */
    const char *dim;     /* detalle de -v: tenue */
    const char *reset;
} palette_t;

static palette_t C = { "", "", "", "", "", "", "", "" };

/*
 * Colores sólo si la salida es una terminal (al redirigir a un archivo o
 * a tee no se ensucia el log con códigos ANSI), salvo que se pida con -c.
 * Se respeta la convención NO_COLOR (https://no-color.org).
 */
static void setup_colors(int force) {
    int enable = force || (isatty(STDOUT_FILENO) && getenv("NO_COLOR") == NULL);
    if (!enable) return;
    C = (palette_t){
        .hop   = "\033[32m",
        .name  = "\033[36m",
        .ip    = "\033[31m",
        .time  = "\033[33m",
        .star  = "\033[35m",
        .note  = "\033[1;31m",
        .dim   = "\033[2m",
        .reset = "\033[0m",
    };
}

/* ------------------------------------------------------------------ */
/* Utilidades                                                          */
/* ------------------------------------------------------------------ */

static double now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1000.0 + ts.tv_nsec / 1e6;
}

static void sleep_ms(int ms) {
    struct timespec ts = { ms / 1000, (long)(ms % 1000) * 1000000L };
    while (nanosleep(&ts, &ts) < 0 && errno == EINTR) { }
}

static const char *ip_str(uint32_t addr, char *buf) {
    struct in_addr in = { addr };
    return inet_ntop(AF_INET, &in, buf, INET_ADDRSTRLEN);
}

/*
 * La línea de cada salto se va armando por partes. Sin -v se imprime
 * conforme llegan las respuestas (como el traceroute real); con -v se
 * imprime al final del salto, debajo del detalle de cada probe.
 */
static char hop_line[4096];
static size_t hop_line_len;

static void emit(const options_t *opt, const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(hop_line + hop_line_len, sizeof(hop_line) - hop_line_len, fmt, ap);
    va_end(ap);
    if (n < 0) return;
    if (!opt->verbose) {
        fputs(hop_line + hop_line_len, stdout);
        fflush(stdout);
    }
    hop_line_len += (size_t)n;
    if (hop_line_len >= sizeof(hop_line)) hop_line_len = sizeof(hop_line) - 1;
}

/* "nombre (ip)", o sólo "ip" con -n, igual que el traceroute del sistema */
static void emit_addr(const options_t *opt, uint32_t addr) {
    char ip[INET_ADDRSTRLEN];
    ip_str(addr, ip);

    if (opt->numeric) {
        emit(opt, " %s%s%s", C.ip, ip, C.reset);
        return;
    }
    char name[NI_MAXHOST];
    lookup_hop_name(addr, name, sizeof(name));
    emit(opt, " %s%s%s (%s%s%s)", C.name, name, C.reset, C.ip, ip, C.reset);
}

/* ------------------------------------------------------------------ */
/* Recepción                                                           */
/* ------------------------------------------------------------------ */

/*
 * Espera la respuesta ICMP que corresponde al probe con puerto destino
 * 'dst_port', hasta 'deadline' (ms). Cualquier otro ICMP (pings de otros
 * programas, respuestas tardías de probes anteriores) se descarta.
 * Retorna 1 si llegó la respuesta, 0 si hubo timeout.
 */
static int wait_reply(const trace_ctx_t *ctx, uint16_t dst_port, double deadline,
                      icmp_reply_t *reply, double *recv_time) {
    uint8_t buf[1500];

    for (;;) {
        double remaining = deadline - now_ms();
        if (remaining <= 0) return 0;

        struct pollfd pfd = { ctx->recv_fd, POLLIN, 0 };
        int rc = poll(&pfd, 1, (int)remaining + 1);
        if (rc < 0) {
            if (errno == EINTR) continue;
            perror("[traceroute] poll");
            return 0;
        }
        if (rc == 0) return 0;

        ssize_t n = recv(ctx->recv_fd, buf, sizeof(buf), 0);
        double t = now_ms();
        if (n <= 0) continue;

        if (parse_icmp_reply(buf, (size_t)n, reply) != 0) continue;

        /* ¿La copia del probe que viene dentro del ICMP es la nuestra? */
        if (reply->inner_dst   != ctx->dst_addr ||
            reply->inner_sport != ctx->src_port ||
            reply->inner_dport != dst_port) {
            continue;
        }

        *recv_time = t;
        return 1;
    }
}

/* Anotación tipo traceroute para Destination Unreachable que no es "puerto" */
static const char *unreach_note(uint8_t code) {
    switch (code) {
        case ICMP_CODE_NET_UNREACH:   return "!N";
        case ICMP_CODE_HOST_UNREACH:  return "!H";
        case ICMP_CODE_PROTO_UNREACH: return "!P";
        case ICMP_CODE_PORT_UNREACH:  return "";
        case ICMP_CODE_ADMIN_PROHIB:  return "!X";
        default:                      return "!?";
    }
}

/* Nombre legible del mensaje ICMP, para -v */
static const char *icmp_name(uint8_t type, uint8_t code) {
    if (type == ICMP_TYPE_TIME_EXCEEDED) return "Time Exceeded";
    switch (code) {
        case ICMP_CODE_NET_UNREACH:   return "Net Unreachable";
        case ICMP_CODE_HOST_UNREACH:  return "Host Unreachable";
        case ICMP_CODE_PROTO_UNREACH: return "Protocol Unreachable";
        case ICMP_CODE_PORT_UNREACH:  return "Port Unreachable";
        case ICMP_CODE_ADMIN_PROHIB:  return "Admin Prohibited";
        default:                      return "Destination Unreachable";
    }
}

/* ------------------------------------------------------------------ */
/* Bucle principal                                                     */
/* ------------------------------------------------------------------ */

static void run_trace(const options_t *opt, const trace_ctx_t *ctx) {
    uint8_t packet[PROBE_PACKET_LEN];
    unsigned seq = 0;        /* número global de probe: define el puerto destino */
    int reached = 0;

    for (int ttl = opt->first_ttl; ttl <= opt->max_hops && !reached; ttl++) {
        uint32_t last_addr = 0;
        int have_last = 0;

        hop_line_len = 0;
        emit(opt, "%s%2d%s ", C.hop, ttl, C.reset);
        if (opt->verbose) printf("\n%s-- TTL %d --%s\n", C.hop, ttl, C.reset);

        for (int p = 0; p < opt->probes; p++) {
            if (seq > 0 && opt->pause_ms > 0) sleep_ms(opt->pause_ms);

            uint16_t dst_port = (uint16_t)(opt->base_port + seq);
            uint16_t ip_id    = (uint16_t)(seq + 1);
            seq++;

            size_t len = build_probe(packet, ctx->src_addr, ctx->dst_addr,
                                     ctx->src_port, dst_port, (uint8_t)ttl, ip_id);

            double sent_at = now_ms();
            if (send_probe(ctx->send_fd, packet, len, ctx->dst_addr) < 0) {
                exit(1);
            }
            /* -v: una línea por probe: lo que sale  ->  lo que vuelve */
            if (opt->verbose) {
                printf("%s   probe %d  id=%-4u UDP %u -> %u  %zu B  %s",
                       C.dim, p + 1, ip_id, ctx->src_port, dst_port, len, C.reset);
                fflush(stdout);
            }

            icmp_reply_t reply;
            double recv_at;
            if (!wait_reply(ctx, dst_port, sent_at + opt->wait_sec * 1000.0, &reply, &recv_at)) {
                if (opt->verbose) {
                    printf("<-  %s*%s %stimeout (%.1f s)%s\n",
                           C.star, C.reset, C.dim, opt->wait_sec, C.reset);
                }
                emit(opt, " %s*%s", C.star, C.reset);
                continue;
            }

            if (opt->verbose) {
                char ip[INET_ADDRSTRLEN];
                printf("<-  ICMP %u/%u %-16s de %s%-15s%s  %s%.3f ms%s\n",
                       reply.type, reply.code, icmp_name(reply.type, reply.code),
                       C.ip, ip_str(reply.from, ip), C.reset,
                       C.time, recv_at - sent_at, C.reset);
            }

            /* Como el traceroute real: el nombre sólo se repite si cambia el router */
            if (!have_last || reply.from != last_addr) {
                emit_addr(opt, reply.from);
                last_addr = reply.from;
                have_last = 1;
            }
            emit(opt, "  %s%.3f ms%s", C.time, recv_at - sent_at, C.reset);

            if (reply.type == ICMP_TYPE_DEST_UNREACH) {
                const char *note = unreach_note(reply.code);
                if (*note) emit(opt, " %s%s%s", C.note, note, C.reset);
                reached = 1;   /* terminamos al cerrar este salto */
            }
        }

        if (opt->verbose) fputs(hop_line, stdout);
        printf("\n");
        fflush(stdout);
    }
}

/* ------------------------------------------------------------------ */
/* Argumentos                                                          */
/* ------------------------------------------------------------------ */

static void usage(const char *prog) {
    fprintf(stderr,
        "Uso: sudo %s [opciones] host\n"
        "  -f ttl     TTL inicial                          (default %d)\n"
        "  -m hops    cantidad maxima de saltos            (default %d)\n"
        "  -q n       probes por salto                     (default %d)\n"
        "  -w seg     tiempo de espera por respuesta, seg  (default %.0f)\n"
        "  -z ms      pausa entre probes, milisegundos     (default %d)\n"
        "  -p puerto  puerto UDP destino base              (default %d)\n"
        "  -n         no resolver nombres (solo IPs)\n"
        "  -v         mostrar cada probe enviado y cada ICMP recibido\n"
        "  -c         forzar colores (por defecto solo en terminal; NO_COLOR los apaga)\n",
        prog, DEFAULT_FIRST_TTL, DEFAULT_MAX_HOPS, DEFAULT_PROBES,
        DEFAULT_WAIT_SEC, DEFAULT_PAUSE_MS, DEFAULT_BASE_PORT);
    exit(2);
}

static long parse_int(const char *s, long min, long max, const char *what) {
    char *end;
    errno = 0;
    long v = strtol(s, &end, 10);
    if (errno || *end != '\0' || v < min || v > max) {
        fprintf(stderr, "Valor invalido para %s: '%s' (rango %ld..%ld)\n", what, s, min, max);
        exit(2);
    }
    return v;
}

static options_t parse_options(int argc, char **argv) {
    options_t opt = {
        .first_ttl = DEFAULT_FIRST_TTL,
        .max_hops  = DEFAULT_MAX_HOPS,
        .probes    = DEFAULT_PROBES,
        .wait_sec  = DEFAULT_WAIT_SEC,
        .pause_ms  = DEFAULT_PAUSE_MS,
        .base_port = DEFAULT_BASE_PORT,
    };

    int c;
    while ((c = getopt(argc, argv, "f:m:q:w:z:p:nvch")) != -1) {
        switch (c) {
            case 'f': opt.first_ttl = (int)parse_int(optarg, 1, 255, "-f"); break;
            case 'm': opt.max_hops  = (int)parse_int(optarg, 1, 255, "-m"); break;
            case 'q': opt.probes    = (int)parse_int(optarg, 1, 10, "-q"); break;
            case 'z': opt.pause_ms  = (int)parse_int(optarg, 0, 60000, "-z"); break;
            case 'p': opt.base_port = (int)parse_int(optarg, 1, 65000, "-p"); break;
            case 'w': {
                char *end;
                opt.wait_sec = strtod(optarg, &end);
                if (*end != '\0' || opt.wait_sec <= 0 || opt.wait_sec > 60) {
                    fprintf(stderr, "Valor invalido para -w: '%s' (0 < seg <= 60)\n", optarg);
                    exit(2);
                }
                break;
            }
            case 'n': opt.numeric = 1; break;
            case 'v': opt.verbose = 1; break;
            case 'c': opt.color = 1; break;
            default:  usage(argv[0]);
        }
    }
    if (optind != argc - 1) usage(argv[0]);
    opt.host = argv[optind];

    if (opt.first_ttl > opt.max_hops) {
        fprintf(stderr, "El TTL inicial (%d) no puede ser mayor que los saltos maximos (%d)\n",
                opt.first_ttl, opt.max_hops);
        exit(2);
    }
    return opt;
}

int main(int argc, char **argv) {
    options_t opt = parse_options(argc, argv);
    trace_ctx_t ctx;

    setup_colors(opt.color);

    if (resolve_target(opt.host, &ctx.dst_addr) != 0) return 1;
    if (get_source_addr(ctx.dst_addr, &ctx.src_addr) != 0) return 1;

    ctx.send_fd = open_send_socket();
    if (ctx.send_fd < 0) return 1;
    ctx.recv_fd = open_recv_socket();
    if (ctx.recv_fd < 0) return 1;

    /* Puerto origen derivado del PID (como el traceroute clásico) */
    ctx.src_port = (uint16_t)((getpid() & 0x7FFF) | 0x8000);

    char dst_ip[INET_ADDRSTRLEN], src_ip[INET_ADDRSTRLEN];
    printf("traceroute to %s (%s%s%s), %d hops max, %d byte packets\n",
           opt.host, C.ip, ip_str(ctx.dst_addr, dst_ip), C.reset,
           opt.max_hops, PROBE_PACKET_LEN);
    if (opt.verbose) {
        printf("%s   origen %s:%u | TTL inicial %d | %d probes/salto | espera %.1f s | pausa %d ms%s\n",
               C.dim, ip_str(ctx.src_addr, src_ip), ctx.src_port, opt.first_ttl,
               opt.probes, opt.wait_sec, opt.pause_ms, C.reset);
    }
    fflush(stdout);

    run_trace(&opt, &ctx);

    close(ctx.send_fd);
    close(ctx.recv_fd);
    return 0;
}
