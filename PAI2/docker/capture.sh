#!/usr/bin/env bash
# docker/capture.sh - Sniffer del gateway (RS4)
# Corre dentro del contenedor 'sniffer', que comparte la red del gateway.
# Captura todo el tráfico de los puertos del túnel en un .pcap con marca de tiempo.
set -euo pipefail

OUT_DIR="/app/evidence/pcap"
mkdir -p "$OUT_DIR"
STAMP="$(date +%Y%m%d_%H%M%S)"
OUT="$OUT_DIR/gateway_live_${STAMP}.pcap"

echo "[sniffer] Capturando puertos 8443 y 9443 en $OUT (Ctrl-C para parar)"
exec tcpdump -i any -w "$OUT" -U "tcp port 8443 or tcp port 9443 or tcp port 9080"
