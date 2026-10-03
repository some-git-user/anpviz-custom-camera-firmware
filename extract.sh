#!/usr/bin/env bash
# Extract the ANJOY888 firmware into an editable tree.
#   usage: ./extract.sh [input.bin] [workdir]
set -euo pipefail
cd "$(dirname "$0")"

IN="${1:-firmware_MC500L_V0_AF-RTMP-H5_V3.2.1.2_Y_EN_YM500L_V0_202301101555.bin}"
WORK="${2:-work}"

[ -f "$IN" ] || { echo "input not found: $IN"; exit 1; }

rm -rf "$WORK"
python3 tools/anjoy.py unpack "$IN" "$WORK"

echo
echo "Extracted. Web UI is in: $WORK/rootfs/var/www/"
echo "Edit those files, then run: ./pack.sh"
