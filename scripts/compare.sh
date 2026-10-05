#!/bin/bash
# Corre mytraceroute y el traceroute del sistema con los MISMOS parámetros
# y guarda ambas salidas en logs/ para compararlas (evidencia para el video).
#
# Uso:   sudo ./scripts/compare.sh [opciones] host
# Ej.:   sudo ./scripts/compare.sh -n -q 3 -w 2 galileo.edu
#
# Las opciones -f -m -q -w -z -n se pasan igual a ambos programas.
set -euo pipefail

if [ $# -lt 1 ]; then
    echo "Uso: sudo $0 [opciones] host" >&2
    exit 2
fi

cd "$(dirname "$0")/.."

if [ ! -x ./mytraceroute ]; then
    echo "No existe ./mytraceroute: compila primero con 'make' (sin sudo)" >&2
    exit 1
fi

mkdir -p logs
STAMP=$(date +%Y%m%d-%H%M%S)

# Último argumento = host, el resto = opciones
HOST="${!#}"
SAFE_HOST=$(echo "$HOST" | tr -c 'A-Za-z0-9.-\n' '_')
OURS="logs/${STAMP}_${SAFE_HOST}_mytraceroute.log"
SYS="logs/${STAMP}_${SAFE_HOST}_sistema.log"

# Con sudo los archivos quedarían de root: se los devolvemos al usuario real
give_back_logs() {
    if [ -n "${SUDO_USER:-}" ]; then
        chown "$SUDO_USER" logs "$OURS" "$SYS" 2>/dev/null || true
    fi
}
trap give_back_logs EXIT

echo "===== mytraceroute $* ====="
if ! ./mytraceroute "$@" | tee "$OURS"; then
    echo "mytraceroute falló; no se corre el traceroute del sistema" >&2
    rm -f "$OURS"
    exit 1
fi

echo
if [ "$(uname -s)" = "Linux" ]; then
    # Mismos defaults que el nuestro. -N 1 desactiva los probes en paralelo
    # del traceroute de Linux (por defecto manda 16 a la vez).
    # En Linux, -z mayor que 10 se interpreta como milisegundos.
    echo "===== traceroute -N 1 -m 64 -q 3 -w 3 -z 100 $* ====="
    traceroute -N 1 -m 64 -q 3 -w 3 -z 100 "$@" | tee "$SYS"
else
    # macOS: -z ya está en milisegundos; no tiene -N (siempre es secuencial)
    echo "===== traceroute -m 64 -q 3 -w 3 -z 100 $* ====="
    traceroute -m 64 -q 3 -w 3 -z 100 "$@" | tee "$SYS"
fi

echo
echo "Logs guardados en: $OURS y $SYS"
