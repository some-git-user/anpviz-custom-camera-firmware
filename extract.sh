#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# Unpack an ANJOY888 camera firmware image into an editable build tree.
#
#   usage: ./extract.sh <firmware.bin> [--force] [--as SLUG]
#
# The camera slug (e.g. YM500L, YMF46D) and firmware version are read from the
# image header (device_name @ 0x128), so the working directory is always derived
# from the firmware itself -- not guessed from the filename.
#
#   builds/<slug>/rootfs/     the editable root filesystem (tracked in git)
#   builds/<slug>/header.bin  header+kernel, kept verbatim for repack (tracked)
#
# Options:
#   --force      overwrite an existing builds/<slug>/rootfs tree
#   --as <slug>  override the auto-detected slug
#
# Compressed inputs (.xz / .gz / .zst) are decompressed transparently.
# ---------------------------------------------------------------------------
set -euo pipefail
cd "$(dirname "$0")"

FORCE=0
SLUG_OVERRIDE=""
IN=""

while [ $# -gt 0 ]; do
    case "$1" in
        --force)   FORCE=1; shift ;;
        --as)      SLUG_OVERRIDE="${2:-}"; [ -n "$SLUG_OVERRIDE" ] || { echo "--as needs a slug"; exit 1; }; shift 2 ;;
        -h|--help) sed -n '2,18p' "$0"; exit 0 ;;
        -*)        echo "unknown option: $1"; exit 1 ;;
        *)         IN="$1"; shift ;;
    esac
done

[ -n "$IN" ] || { echo "usage: ./extract.sh <firmware.bin> [--force] [--as SLUG]"; exit 1; }
[ -f "$IN" ] || { echo "input not found: $IN"; exit 1; }

# --- transparently decompress .xz / .gz / .zst inputs into a temp file -------
TMPDIR_X=""
cleanup() { [ -n "$TMPDIR_X" ] && rm -rf "$TMPDIR_X"; }
trap cleanup EXIT
REAL="$IN"
case "$IN" in
    *.xz)  TMPDIR_X="$(mktemp -d)"; REAL="$TMPDIR_X/firmware.bin"; xz -dc "$IN" > "$REAL" ;;
    *.gz)  TMPDIR_X="$(mktemp -d)"; REAL="$TMPDIR_X/firmware.bin"; gzip -dc "$IN" > "$REAL" ;;
    *.zst) TMPDIR_X="$(mktemp -d)"; REAL="$TMPDIR_X/firmware.bin"; zstd -dc -q "$IN" > "$REAL" ;;
esac

# --- derive slug + version from the header ----------------------------------
read -r SLUG VER <<<"$(python3 tools/anjoy.py slug "$REAL")"
[ -n "$SLUG" ] || { echo "could not detect camera slug from $IN"; exit 1; }
[ -z "$SLUG_OVERRIDE" ] || SLUG="$SLUG_OVERRIDE"
DEVNAME="$(python3 tools/anjoy.py devname "$REAL")"

OUT="builds/$SLUG"
echo "firmware : $IN"
echo "device   : $DEVNAME"
echo "camera   : $SLUG  (firmware v${VER:-?})"
echo "target   : $OUT/"

if [ -d "$OUT/rootfs" ] && [ "$FORCE" != "1" ]; then
    echo
    echo "ERROR: $OUT/rootfs already exists." >&2
    echo "       Your edits live there -- refusing to overwrite." >&2
    echo "       Re-run with --force to replace it with a fresh extraction." >&2
    exit 1
fi

[ "$FORCE" = "1" ] && rm -rf "$OUT/rootfs"
mkdir -p "$OUT"
python3 tools/anjoy.py unpack "$REAL" "$OUT"

# unpack writes header.bin, rootfs.squashfs, tail.bin and rootfs/ into $OUT.
# The squashfs + tail are reproducible artifacts; drop them to keep the tree tidy.
rm -f "$OUT/rootfs.squashfs" "$OUT/tail.bin"

echo
echo "Extracted. Edit the web UI in: $OUT/rootfs/var/www/"
echo "Then build with:               ./pack.sh $SLUG <name>"
