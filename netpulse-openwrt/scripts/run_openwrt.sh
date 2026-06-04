#!/bin/sh

set -eu

IFACE="${1:-br-lan}"
PORT="${2:-8080}"
BASE_DIR="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"

chmod +x "$BASE_DIR/scripts/firewall.sh" || true

exec "$BASE_DIR/netpulse_server" \
    -i "$IFACE" \
    -p "$PORT" \
    -w "$BASE_DIR/web" \
    -s "$BASE_DIR/scripts/firewall.sh"
