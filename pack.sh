#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# Repack an edited build tree into a flashable ANJOY888 firmware image.
#
#   usage: ./pack.sh <slug> [name]
#          ./pack.sh YMF46D custom1
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
#   CAM_IP       camera IP, used to name the recovery-password store.
#                If unset and run from a terminal you are asked for it.
#                Non-interactive with no CAM_IP uses the shared store.
# ---------------------------------------------------------------------------
set -euo pipefail
cd "$(dirname "$0")"

SLUG="${1:-}"
NAME="${2:-}"

[ -n "$SLUG" ] || { echo "usage: ./pack.sh <slug> [name]   (e.g. ./pack.sh YMF46D custom1)"; echo; echo "Available build trees:"; ls -1 builds/ 2>/dev/null || echo "  (none)"; exit 1; }

BUILD="builds/$SLUG"
HTTPS_PASS="${HTTPS_PASS:-homecam}"
HTTPS_CN="${HTTPS_CN:-homecamera.lan}"
HTTPS_DAYS="${HTTPS_DAYS:-3650}"
RECOVERY_PASS="${RECOVERY_PASS:-}"
# Custom build tag. Leave unset to auto-increment "<stock version>-custom<N>";
# set it to pin an exact tag (e.g. CUSTOM_TAG=3.4.5.2-custom7).
CUSTOM_TAG="${CUSTOM_TAG:-}"

[ -d "$BUILD/rootfs" ] || { echo "no build tree: $BUILD/rootfs (run ./extract.sh first)"; exit 1; }
[ -f "$BUILD/header.bin" ] || { echo "missing $BUILD/header.bin (run ./extract.sh first)"; exit 1; }

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

# --- recovery telnet password: STABLE PER CAMERA ---------------------------
# reclogin.sh reads /opt/ch/reclogin.pass at login time. The file is gitignored,
# so the password never lands in the repo.
#
# The per-camera file tools/.reclogin_pass.<ip> is the source of truth:
#   * exists  -> REUSE it. Build 100 times, the password never changes, so
#                telnet keeps working whether or not you have flashed yet.
#   * missing -> generate one and PERSIST it there, so it is stable from then on.
#   * RECOVERY_PASS=... -> force a new password and overwrite the file (rotate).
# The flashed image and tools/ read the same file, so they never disagree.
#
# The address is only here to NAME the password store, so two cameras do not
# share a file. Building itself does not need one. So:
#   CAM_IP=... ./pack.sh ...   -> used directly
#   run from a terminal        -> you are asked once
#   non-interactive, no IP   -> fall back to the single shared store
#                              tools/.reclogin_pass (ctl3.exp reads that too),
#                              so CI/cron builds still work.
CAM_IP="${CAM_IP:-}"
if [ -z "$CAM_IP" ] && [ -t 0 ]; then
    printf 'camera IP for the recovery-password store (blank = shared store): ' >&2
    IFS= read -r CAM_IP || CAM_IP=""
    CAM_IP="${CAM_IP//[[:space:]]/}"
fi
PASS_STORE=""
if [ -n "$CAM_IP" ]; then
    PASS_STORE="tools/.reclogin_pass.$CAM_IP"
else
    # No address: use the single shared store. ctl3.exp falls back to this same
    # file when it has no per-host file, so the two always agree.
    PASS_STORE="tools/.reclogin_pass"
    echo "  no camera IP -- using the shared store $PASS_STORE" >&2
fi

if [ -n "$RECOVERY_PASS" ]; then
    # Explicit rotation.
    REC_PASS="$RECOVERY_PASS"
    echo "Recovery telnet password: (forced via RECOVERY_PASS -- rotating)"
elif [ -n "$PASS_STORE" ] && [ -s "$PASS_STORE" ]; then
    # Stable path: reuse the camera's existing password.
    IFS= read -r REC_PASS < "$PASS_STORE"
    REC_PASS="${REC_PASS%$'\r'}"
    echo "Recovery telnet password: (reused $PASS_STORE -- stable for $CAM_IP)"
else
    REC_PASS="$(tr -dc 'A-Za-z0-9' </dev/urandom 2>/dev/null | head -c 12)$(date +%s | tail -c 5)"
    if [ -z "$REC_PASS" ]; then
        REC_PASS="rec$(openssl rand -hex 8 2>/dev/null || echo changeme)"
    fi
    echo "Recovery telnet password: $REC_PASS (new; persisted for this camera)"
fi
[ -n "$REC_PASS" ] || { echo "ERROR: empty recovery password" >&2; exit 1; }

printf '%s\n' "$REC_PASS" > "$CERT_DIR/reclogin.pass"
chmod 600 "$CERT_DIR/reclogin.pass"
# Persist as the per-camera source of truth so the next build reuses it.
if [ -n "$PASS_STORE" ]; then
    printf '%s\n' "$REC_PASS" > "$PASS_STORE"
    chmod 600 "$PASS_STORE"
    echo "  stored -> $PASS_STORE (ctl3.exp reads this; stable across builds)"
fi

# Keep etc/passwd_sys consistent (best-effort; reclogin.sh is the real gate).
# rcS copies it to /tmp/passwd for the serial-console login fallback. It holds
# an md5-crypt of the recovery password, so it is gitignored -- generated into
# the image every build but never committed.
if command -v openssl >/dev/null 2>&1; then
    HASH="$(openssl passwd -1 "$REC_PASS" 2>/dev/null || true)"
    if [ -n "$HASH" ]; then
        printf 'root:%s:0:0:root:/root:/bin/sh\n' "$HASH" > "$BUILD/rootfs/etc/passwd_sys"
    fi
fi

# --- stamp the custom build version into the rootfs -------------------------
# Build identity scheme:  <stock version>-custom<N>   e.g. V3.4.5.2-custom1
# The base version comes from build.info (recorded at extract time), so the tag
# follows the stock firmware we are actually based on. N auto-increments per
# build from builds/<slug>/custom_build. Override with CUSTOM_TAG=... to pin it.
BASE_VER="$(sed -n 's/^version=//p' "$BUILD/build.info" 2>/dev/null | head -1)"
[ -n "$BASE_VER" ] || BASE_VER="0.0.0"
# `|| true` is REQUIRED: under `set -o pipefail`, a camera that has never been
# custom-built has no custom_build file, so `cat` exits 1 and would abort the
# whole pipeline on a fresh tree.
CUR_N="$(cat "$BUILD/custom_build" 2>/dev/null | tr -dc '0-9' || true)"
[ -n "$CUR_N" ] || CUR_N=0

if [ -n "$CUSTOM_TAG" ]; then
    TAG="$CUSTOM_TAG"
    # A pinned tag must STILL advance the counter, otherwise it drifts behind
    # reality and the next UNPINNED build reuses a number already handed out --
    # two distinct images claiming one version string. Bump the counter to at
    # least the pinned number so auto-increment resumes above it.
    PINNED_N="$(printf '%s' "$CUSTOM_TAG" | sed -n 's/.*custom\([0-9][0-9]*\).*/\1/p')"
    if [ -n "$PINNED_N" ] && [ "$PINNED_N" -gt "$CUR_N" ]; then
        echo "$PINNED_N" > "$BUILD/custom_build"
        CUR_N="$PINNED_N"
    fi
else
    N=$((CUR_N + 1))
    echo "$N" > "$BUILD/custom_build"
    TAG="${BASE_VER}-custom${N}"
fi
BUILD_DATE="$(date '+%Y-%m-%d %H:%M:%S')"
# Preserve the vendor's own prefix (e.g. "_Y_EN-RTMP-H5_L") and only replace the
# version token + build date, so we never drift the model string by accident.
PREFIX=""
if [ -f "$BUILD/rootfs/etc/filesys.ver" ]; then
    PREFIX="$(sed -n 's/^\( *[^V]*\)V.*/\1/p' "$BUILD/rootfs/etc/filesys.ver" | head -1)"
fi
[ -n "$PREFIX" ] || PREFIX="_Y_EN-RTMP-H5_L "
printf '%sV%s build %s \n' "$PREFIX" "$TAG" "$BUILD_DATE" > "$BUILD/rootfs/etc/filesys.ver"
printf 'custom build %s (%s) at %s\n' "$TAG" "$SLUG" "$BUILD_DATE" > "$BUILD/rootfs/var/www/CUSTOM_BUILD.txt"
echo "Build tag: V$TAG   (counter -> $(cat "$BUILD/custom_build" 2>/dev/null))"
# Default the output filename to the build tag when no explicit name was given.
[ -n "$NAME" ] || NAME="${TAG}"
OUT="out/${SLUG}_${NAME}.bin"

# --- rebuild the Nagios CGI auth shim from source ---------------------------
# The shim (opt/ch/nagios_authd.so) is cross-compiled from
# tools/nagios_shim/nagios_authd.c. Rebuild it here on every pack so we never
# ship a stale .so after editing the C source. Override the toolchain with
# TC_PREFIX=...
#
# OPT-IN PER CAMERA. The shim is NOT portable across our targets: it assumes the
# vendor libcgibin_curl.so CGI ABI (http_cgi_find / http_cgi_handle, 3 args,
# calloc(102400) out buffer) AND uClibc. YM500L is a different platform --
# glibc (libc.so.6 / ld-linux-armhf.so.3) and has no libcgibin_curl.so at all,
# so a shim built for YMF46D would be dead weight there (and could not resolve
# its symbols).
#
# So we only build it when THIS build tree is actually wired for it, detected by
# rcS referencing nagios_authd. To port the feature to another camera you must
# first port the shim (verify that platform's CGI ABI + libc) and add the
# LD_PRELOAD block to its rcS -- then pack.sh picks it up automatically.
SHIM_SRC="tools/nagios_shim/nagios_authd.c"
SHIM_DEST="$BUILD/rootfs/opt/ch/nagios_authd.so"
RC_S="$BUILD/rootfs/etc/init.d/rcS"
TC_PREFIX="${TC_PREFIX:-/home/user/toolchains/armv7-eabihf--uclibc--stable-2024.05-1/bin/arm-buildroot-linux-uclibcgnueabihf}"

if [ ! -f "$RC_S" ] || ! grep -q 'nagios_authd' "$RC_S"; then
    echo "Nagios shim: not wired into this tree's rcS -- skipping (opt-in)."
    echo "           (see tools/nagios_shim/nagios_authd.c before porting to $SLUG)"
elif [ ! -f "$SHIM_SRC" ]; then
    if [ -f "$SHIM_DEST" ]; then
        echo "WARNING: rcS wants the shim but $SHIM_SRC is missing." >&2
        echo "         Packing the EXISTING $SHIM_DEST unchanged -- it may be" >&2
        echo "         STALE. Continuing." >&2
    else
        echo "WARNING: rcS wants the shim but neither source nor prebuilt .so exists." >&2
        echo "         rcS's [ -f ] guard makes this a harmless no-op: the" >&2
        echo "         authenticated /cgi-bin/nagios route will simply be absent." >&2
    fi
elif [ ! -x "${TC_PREFIX}-gcc" ]; then
    echo "ERROR: rcS requires the Nagios shim but the toolchain is missing:" >&2
    echo "       ${TC_PREFIX}-gcc" >&2
    echo "       Refusing to pack -- shipping a stale/absent shim would leave" >&2
    echo "       the tree in an inconsistent state." >&2
    echo "       Set TC_PREFIX=/path/to/arm-linux-gnueabihf-triple to build." >&2
    exit 1
else
    # Guard against an ABI mismatch: this toolchain targets uClibc. If the rootfs
    # is glibc-based the shim would not load, so fail loudly instead of booting
    # a web_server that silently cannot preload.
    if [ -e "$BUILD/rootfs/lib/libc.so.6" ] && [ ! -e "$BUILD/rootfs/lib/libc.so.0" ]; then
        echo "ERROR: $SLUG rootfs looks glibc-based (libc.so.6, no libc.so.0)." >&2
        echo "       The Nagios shim in tools/nagios_shim/ is built for uClibc" >&2
        echo "       1.0.31 and will NOT load here. Port it first (see the note" >&2
        echo "       above) or remove the nagios_authd lines from rcS." >&2
        exit 1
    fi
    echo "Cross-compiling Nagios shim: $SHIM_SRC -> $SHIM_DEST"
    "${TC_PREFIX}-gcc" -O2 -fPIC -shared -o "$SHIM_DEST" "$SHIM_SRC" \
        || { echo "ERROR: shim compile failed -- refusing to pack a stale .so" >&2; exit 1; }
    chmod 755 "$SHIM_DEST"
    echo "  exports: $(${TC_PREFIX}-nm -D --defined-only "$SHIM_DEST" | awk '$2=="T"{printf "%s ", $3}')"
fi

# --- normalise executable bits on shell scripts -----------------------------
# squashfs preserves unix modes, so a script that lost its exec bit in the tree
# (or in git) boots non-executable -- which would silently break any rcS guard
# like `[ -x /opt/ch/telnetd_ctl.sh ]`. Make every shell script in the tree
# executable before packing.
echo "Normalising exec bits on shell scripts..."
find "$BUILD/rootfs" -type f -name '*.sh' -exec chmod 755 {} +
[ -f "$BUILD/rootfs/etc/init.d/rcS" ] && chmod 755 "$BUILD/rootfs/etc/init.d/rcS"

echo "Packing $BUILD/rootfs -> $OUT ..."
python3 tools/anjoy.py repack "$BUILD/rootfs" "$BUILD/header.bin" "$OUT"

echo
echo "Built: $OUT"
echo "  camera:         $SLUG"
echo "  recovery login: root / $REC_PASS"
sha256sum "$OUT"
