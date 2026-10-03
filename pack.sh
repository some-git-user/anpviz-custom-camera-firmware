#!/usr/bin/env bash
# Repack the edited tree into a flashable firmware .bin.
#   usage: ./pack.sh [workdir] [output.bin]
#
# A fresh self-signed TLS cert/key/passphrase is generated into the rootfs on
# every repack (opt/ch/https.{crt,key,pwd}). The web_server copies these to
# /mnt/nand/ at boot and serves HTTPS with them. The key material is NOT kept
# in git (.gitignore) -- it is regenerated here so each build gets its own cert.
#
# Override the passphrase with HTTPS_PASS=... ; defaults to "homecam".
# Override the cert subject with HTTPS_CN=... ; defaults to "homecamera.lan".
set -euo pipefail
cd "$(dirname "$0")"

WORK="${1:-work}"
OUT="${2:-firmware_custom.bin}"
HTTPS_PASS="${HTTPS_PASS:-homecam}"
HTTPS_CN="${HTTPS_CN:-homecamera.lan}"
HTTPS_DAYS="${HTTPS_DAYS:-3650}"
# Recovery telnet password. Set RECOVERY_PASS=... to choose your own; otherwise a
# random one is generated and printed below (it is NOT stored in git).
RECOVERY_PASS="${RECOVERY_PASS:-}"

[ -d "$WORK/rootfs" ] || { echo "no extracted rootfs in $WORK/rootfs (run ./extract.sh first)"; exit 1; }
[ -f "$WORK/header.bin" ] || { echo "missing $WORK/header.bin (run ./extract.sh first)"; exit 1; }

# --- generate a fresh self-signed TLS cert/key/passphrase into the rootfs ---
if command -v openssl >/dev/null 2>&1; then
    echo "Generating self-signed TLS cert (CN=$HTTPS_CN, $HTTPS_DAYS days)..."
    CERT_DIR="$WORK/rootfs/opt/ch"
    mkdir -p "$CERT_DIR"
    # 2048-bit RSA self-signed cert, unencrypted PKCS#8 key (matches the
    # original layout; the .pwd file is still written for the web_server).
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
CERT_DIR="$WORK/rootfs/opt/ch"
mkdir -p "$CERT_DIR"
if [ -n "$RECOVERY_PASS" ]; then
    REC_PASS="$RECOVERY_PASS"
    echo "Recovery telnet password: (from RECOVERY_PASS env)"
else
    # 16 random chars from a URL-safe-ish alphabet
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
        printf 'root:%s:0:0:root:/root:/bin/sh\n' "$HASH" > "$WORK/rootfs/etc/passwd_sys"
    fi
fi

python3 tools/anjoy.py repack "$WORK/rootfs" "$WORK/header.bin" "$OUT"

echo
echo "Built: $OUT"
echo "  recovery login: root / $REC_PASS"
sha256sum "$OUT"
