# Entorno Linux para compilar y comparar contra el traceroute del sistema
# (el enunciado pide instalarlo con apt-get).
#
#   docker build -t mytraceroute .
#   docker run --rm -it mytraceroute ./scripts/compare.sh -n 1.1.1.1
#
# El usuario root del contenedor ya tiene CAP_NET_RAW, no hace falta --privileged.
FROM debian:bookworm-slim

RUN apt-get update \
 && apt-get install -y --no-install-recommends build-essential traceroute \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY . .
RUN make clean && make && make test

CMD ["./mytraceroute", "-h"]
