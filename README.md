# Proyecto — Traceroute con RAW sockets

Implementación básica de `traceroute` en C. Los datagramas IP + UDP se arman
byte por byte y se envían por un RAW socket con `IP_HDRINCL`; las respuestas
ICMP se leen de un RAW socket ICMP. No se invoca el `traceroute` del sistema
ni se usa ninguna librería de construcción de paquetes.

El código de header IP y checksum viene del **Laboratorio #05**.

## Estructura

```
src/
  traceroute.c   main: argumentos, bucle de TTL, impresión de resultados
  probe.c/.h     arma un probe: header IP + header UDP + 32 bytes de datos
  ip_header.c/.h header IPv4 (del Lab #05, ahora con TTL y protocolo variables)
  udp_header.c/.h header UDP
  checksum.c/.h  Internet checksum (RFC 1071) y checksum UDP con pseudo-header
  icmp_reply.c/.h interpreta las respuestas ICMP (Time Exceeded / Dest Unreachable)
  net.c/.h       sockets, resolución DNS, IP origen
tests/
  test_packets.c pruebas sin root de armado y parseo de paquetes
scripts/
  compare.sh     corre nuestro traceroute y el del sistema con los mismos parámetros
```

## Compilar

Funciona en Linux y macOS, sin dependencias externas.

```sh
make          # genera ./mytraceroute
make test     # pruebas de armado/parseo de paquetes (no necesita root)
make clean
```

## Ejecutar

Los RAW sockets requieren privilegios de root:

```sh
sudo ./mytraceroute galileo.edu
sudo ./mytraceroute -n -q 1 -w 1 8.8.8.8
sudo ./mytraceroute -v -m 5 1.1.1.1     # muestra cada probe y cada ICMP
```

| Opción | Significado | Default |
|---|---|---|
| `-f ttl` | TTL inicial | 1 |
| `-m hops` | cantidad máxima de saltos | 64 |
| `-q n` | probes por salto | 3 |
| `-w seg` | tiempo de espera por respuesta (acepta decimales) | 3 |
| `-z ms` | pausa entre probes, en milisegundos | 100 |
| `-p puerto` | puerto UDP destino base | 33434 |
| `-n` | no resolver nombres (sólo IPs) | — |
| `-v` | detalle de cada probe enviado y cada ICMP recibido | — |

Las opciones van **antes** del host.

## Cómo funciona

```
 nosotros                       router N                          destino
    |  IP(TTL=N) / UDP(:33434+k)    |                                  |
    |------------------------------>|  TTL llega a 0 → lo descarta     |
    |  ICMP 11 Time Exceeded        |                                  |
    |<------------------------------|  (trae copia de nuestro IP+UDP)  |
    |                                                                  |
    |  IP(TTL suficiente) / UDP(:33434+k)                              |
    |----------------------------------------------------------------->|
    |  ICMP 3/3 Port Unreachable  (nadie escucha en ese puerto)        |
    |<-----------------------------------------------------------------|
```

1. **Armado del probe** (`probe.c`): 60 bytes = header IP (20) + header UDP (8) + datos (32).
   - IP: versión 4, IHL 5, `TTL = salto actual`, protocolo 17 (UDP), checksum propio.
   - UDP: puerto origen derivado del PID (identifica esta ejecución), puerto destino
     `33434 + n` distinto para cada probe, checksum con pseudo-header.
2. **Envío**: `socket(AF_INET, SOCK_RAW, IPPROTO_RAW)` + `IP_HDRINCL`, así el kernel
   no toca nuestro header (en particular el TTL).
3. **Recepción**: `socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)` recibe una copia de cada
   ICMP que llega a la máquina, con su header IP.
4. **Correspondencia**: los mensajes de error ICMP incluyen el header IP original y
   los primeros 8 bytes del UDP original. Se acepta una respuesta sólo si ese header
   interno tiene nuestro destino, nuestro puerto origen y el puerto destino del probe
   que se espera. Todo lo demás (pings de otros programas, respuestas tardías) se descarta.
5. **Tiempo**: `clock_gettime(CLOCK_MONOTONIC)` antes del `sendto` y al recibir.
6. **Fin**: al recibir Destination Unreachable (normalmente código 3, Port Unreachable,
   del propio destino) se termina el salto actual y el programa.
   Otros códigos se anotan como el traceroute real: `!N`, `!H`, `!P`, `!X`.

### Particularidad de macOS

Con `IP_HDRINCL`, BSD/macOS espera `total_length` y `flags_fo` en orden del host
(no `htons`). Es el mismo detalle que se resolvió en el Laboratorio #05; está en
`ip_header.c`.

## Pruebas y comparación con el traceroute del sistema

```sh
sudo apt-get install traceroute                  # Linux
sudo ./scripts/compare.sh -n galileo.edu         # guarda ambos logs en logs/
```

El script pasa los mismos parámetros a los dos programas y, en Linux, agrega `-N 1`
para que el traceroute del sistema mande los probes de uno en uno como el nuestro.

Para probar en Linux desde macOS:

```sh
docker build -t mytraceroute .
docker run --rm -it mytraceroute ./scripts/compare.sh -n 1.1.1.1
```

### Diferencias esperadas

| Situación | Por qué |
|---|---|
| El traceroute de Linux por defecto usa 30 saltos y 5 s de espera | Nuestros defaults son los del enunciado (64 saltos, 3 s). El script los iguala. |
| El traceroute de Linux es más rápido | Por defecto manda hasta 16 probes en paralelo; el nuestro es secuencial con 100 ms de pausa. Con `-N 1` se comporta igual. |
| Tiempos distintos en el mismo salto | Son mediciones distintas en momentos distintos; la latencia varía. |
| Varias IPs en un mismo salto | Balanceo de carga (ECMP): cada probe usa otro puerto destino y puede tomar otro camino. Pasa en ambos. |
| `*` en un salto que el otro sí muestra | Muchos routers limitan cuántos ICMP generan por segundo (rate limiting) o no responden. |
| Sólo `*` al final, sin llegar al destino | El destino o un firewall descarta UDP a puertos altos y nunca manda Port Unreachable. |
| Nombre vs. IP | Depende de que exista registro PTR (DNS inverso) y de si se usó `-n`. |
| Tamaño de paquete distinto ("40 byte packets" en macOS, "52" en el ejemplo del enunciado) | Cada implementación usa otra cantidad de datos UDP; el nuestro, igual que Linux, usa 32 (60 bytes en total). |
| En macOS cada router nuevo de un salto sale en otra línea | Es sólo formato: el nuestro, igual que Linux, lo pone en la misma línea. |
