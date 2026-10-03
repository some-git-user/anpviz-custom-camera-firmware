#!/usr/bin/env bash
# Repack the edited tree into a flashable firmware .bin.
#   usage: ./pack.sh [workdir] [output.bin]
set -euo pipefail
cd "$(dirname "$0")"

WORK="${1:-work}"
OUT="${2:-firmware_custom.bin}"

[ -d "$WORK/rootfs" ] || { echo "no extracted rootfs in $WORK/rootfs (run ./extract.sh first)"; exit 1; }
[ -f "$WORK/header.bin" ] || { echo "missing $WORK/header.bin (run ./extract.sh first)"; exit 1; }

python3 tools/anjoy.py repack "$WORK/rootfs" "$WORK/header.bin" "$OUT"

echo
echo "Built: $OUT"
sha256sum "$OUT"
