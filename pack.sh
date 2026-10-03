#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# Repack an edited build tree into a flashable ANJOY888 firmware image.
#
#   usage: ./pack.sh <slug> [name]
#          ./pack.sh YMF46D https10
#          ./pack.sh YM500L
#
# Reads  builds/<slug>/rootfs  +  builds/<slug>/header.bin
# Writes out/<slug>_<name>.bin   (or out/<slug>.bin when [name] is omitted)
#
# A fresh self-signed TLS cert/key/passphrase and a recovery-telnet password are
# generated into the rootfs on every repack. That secret material is gitignored
# and never lands in the repo.
#
# Env overrides:
#   HTTPS_PASS   TLS key passphrase              (default: homecam)
#   HTTPS_CN     TLS cert CN                     (default: homecamera.lan)
#   HTTPS_DAYS   TLS cert validity in days       (default: 3650)
#   RECOVERY_PASS  recovery telnet root password (default: random, printed)
# ---------------------------------------------------------------------------
set -euo pipefail
cd "$(dirname "$0")"

SLUG="${1:-}"
NAME="${2:-}"

[ -n "$SLUG" ] || { echo "usage: ./pack.sh <slug> [name]   (e.g. ./pack.sh YMF46D https10)"; echo; echo "Available build trees:"; ls -1 builds/ 2>/dev/null || echo "  (none)"; exit 1; }

BUILD="builds/$SLUG"
HTTPS_PASS="${HTTPS_PASS:-homecam}"
HTTPS_CN="${HTTPS_CN:-homecamera.lan}"
HTTPS_DAYS="${HTTPS_DAYS:-3650}"
RECOVERY_PASS="${RECOVERY_PASS:-}"

[ -d "$BUILD/rootfs" ] || { echo "no build tree: $BUILD/rootfs (run ./extract.sh first)"; exit 1; }
[ -f "$BUILD/header.bin" ] || { echo "missing $BUILD/header.bin (run ./extract.sh first)"; exit 1; }

if [ -n "$NAME" ]; then OUT="out/${SLUG}_${NAME}.bin"; else OUT="out/${SLUG}.bin"; fi
mkdir -p out

# --- generate a fresh self-signed TLS cert/key/passphrase into the rootfs ---
CERT_DIR="$BUILD/rootfs/opt/ch"
mkdir -p "$CERT_DIR"
if command -v openssl >/dev/null 2>&1; then
    echo "Generating self-signed TLS cert (CN=$HTTPS_CN, $HTTPS_DAYS days)..."
    openssl req -x509 -newkey rsa:2048 -nodes \
        -keyout "$CERT_DIR/https.key" \
        -out    "$CERT_DIR/https.crt" \
        -days   "$HTTPS_DAYS" \
        -subj "/C=DE/ST=Local/L=Local/O=HomeLab/OU=Camera/CN=$HTTPS_CN" \
        >/dev/null 2>&1
    printf '%s' "$HTTPS_PASS" > "$CERT_DIR/https.pwd"
    chmod 644 "$CERT_DIR/https.crt" "$CERT_DIR/https.key" "$CERT_DIR/https.pwd"
    echo "  cert: $CERT_DIR/https.crt"
    openssl x509 -in "$CERT_DIR/https.crt" -noout -subject -dates 2>/dev/null | sed 's/^/    /'
else
    echo "WARNING: openssl not found -- skipping cert generation." >&2
    echo "         HTTPS will not work unless https.{crt,key,pwd} are present." >&2
fi

# --- generate the recovery telnet password file into the rootfs ------------
# reclogin.sh reads /opt/ch/reclogin.pass at login time. The file is gitignored,
# so the password never lands in the repo. Set RECOVERY_PASS=... to pick your own.
if [ -n "$RECOVERY_PASS" ]; then
    REC_PASS="$RECOVERY_PASS"
    echo "Recovery telnet password: (from RECOVERY_PASS env)"
else
    REC_PASS="$(tr -dc 'A-Za-z0-9' </dev/urandom 2>/dev/null | head -c 12)$(date +%s | tail -c 5)"
    if [ -z "$REC_PASS" ]; then
        REC_PASS="rec$(openssl rand -hex 8 2>/dev/null || echo changeme)"
    fi
    echo "Recovery telnet password: $REC_PASS"
fi
printf '%s\n' "$REC_PASS" > "$CERT_DIR/reclogin.pass"
chmod 600 "$CERT_DIR/reclogin.pass"
# keep etc/passwd_sys consistent (best-effort; reclogin.sh is the real gate)
if command -v openssl >/dev/null 2>&1; then
    HASH="$(openssl passwd -1 "$REC_PASS" 2>/dev/null || true)"
    if [ -n "$HASH" ]; then
        printf 'root:%s:0:0:root:/root:/bin/sh\n' "$HASH" > "$BUILD/rootfs/etc/passwd_sys"
    fi
fi

echo "Packing $BUILD/rootfs -> $OUT ..."
python3 tools/anjoy.py repack "$BUILD/rootfs" "$BUILD/header.bin" "$OUT"

echo
echo "Built: $OUT"
echo "  camera:         $SLUG"
echo "  recovery login: root / $REC_PASS"
sha256sum "$OUT"
