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

# Detect the ACTUAL preload assignment, not a mere mention of the name.
# The leading [^#] keeps a comment (even one that names this shim while
# explaining a DIFFERENT shim) from tripping this check. A bare substring
# grep did exactly that and failed the pack for an unrelated reason.
# Matches either the direct `LD_PRELOAD=...nagios_authd` form or the chained
# `NA_PRELOAD=...nagios_authd` assignment used where multiple shims are wired.
if [ ! -f "$RC_S" ] || ! grep -qE '^[[:space:]]*(LD_PRELOAD|NA_PRELOAD)=[^[:space:]]*nagios_authd' "$RC_S"; then
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

# --- rebuild the CVE mitigation shim --------------------------------------
# cve_deny.so (opt/ch/cve_deny.so) interposes fopen/open/popen in web_server
# to close CVE-2024-35343 (/playback/<path> arbitrary file read) and
# CVE-2024-35341 (/config.xml download) without vendor source.
#
# It gates on the CALLER's return address, not just the path, because the
# vendor code legitimately reads /etc/passwd during normal login. The
# addresses it keys on are ABSOLUTE -- web_server is non-PIE -- so they are
# only valid for one specific vendor binary. We therefore verify the target's
# GNU Build ID before shipping: if the vendor ever rebuilds web_server, the
# offsets are stale and we must refuse to pack rather than ship a shim that
# silently protects nothing.
#
# OPT-IN PER CAMERA, same shape as the Nagios shim: detected by rcS naming it.
SHIM_SRC="tools/cve_shim/cve_deny_v2.c"
SHIM_DEST="$BUILD/rootfs/opt/ch/cve_deny.so"
CVE_TEST_SRC="tools/cve_shim/test_deny.c"
# Build ID of the web_server these offsets were derived from, verified against
# both stock and the current tree (md5 088b5a4101bd1a9385dca52a703c775c).
CVE_WEB_SERVER_BUILD_ID="dde0ea728d826aa040c7afeb442f7a34f642e352"
# This shim targets GLIBC. The Nagios shim above targets uClibc. Different
# libc, different internal aliases -- they are not interchangeable.
GLIBC_TC="${GLIBC_TC:-/home/user/toolchains/armv7-eabihf--glibc--stable-2024.05-1/bin/arm-linux}"

# Same rule as above: match the assignment statement, not the name in prose.
if [ ! -f "$RC_S" ] || ! grep -q '^[[:space:]]*CVE_PRELOAD=[^[:space:]]*cve_deny' "$RC_S"; then
    echo "CVE shim: not wired into this tree's rcS -- skipping (opt-in)."
elif [ ! -f "$SHIM_SRC" ]; then
    if [ -f "$SHIM_DEST" ]; then
        echo "WARNING: rcS wants the CVE shim but $SHIM_SRC is missing." >&2
        echo "         Packing the EXISTING $SHIM_DEST unchanged -- it may be STALE." >&2
    else
        echo "WARNING: rcS wants the CVE shim but neither source nor .so exists." >&2
        echo "         rcS's [ -f ] guard makes this a harmless no-op." >&2
    fi
else
    # Resolve the glibc cross compiler. The Bootlin tarball ships both a short
    # `arm-linux-*` and a long `arm-buildroot-linux-gnueabihf-*` prefix.
    CVE_CC="${GLIBC_TC}-gcc"
    if [ ! -x "$CVE_CC" ]; then
        CVE_CC="/home/user/toolchains/armv7-eabihf--glibc--stable-2024.05-1/bin/arm-buildroot-linux-gnueabihf-gcc"
    fi
    if [ ! -x "$CVE_CC" ]; then
        echo "ERROR: rcS requires the CVE shim but no glibc cross compiler was found." >&2
        echo "       Set GLIBC_TC=/path/to/arm-linux-gnueabihf-triple to build it." >&2
        exit 1
    fi

    # ABI GUARD (inverse of the Nagios one): this shim forwards to glibc's
    # _IO_fopen/_IO_popen/__libc_system, which do not exist on uClibc.
    if [ -e "$BUILD/rootfs/lib/libc.so.0" ]; then
        echo "ERROR: $SLUG rootfs looks uClibc-based (libc.so.0 present)." >&2
        echo "       tools/cve_shim forwards to glibc-only symbols and will" >&2
        echo "       NOT load here. Do not enable it on this camera." >&2
        exit 1
    fi
    if [ ! -e "$BUILD/rootfs/lib/libc.so.6" ]; then
        echo "ERROR: $SLUG rootfs has no libc.so.6 -- cannot verify glibc." >&2
        exit 1
    fi

    # BUILD-ID GUARD. The deny rules are absolute addresses in a non-PIE
    # binary. If web_server is not the binary these were derived from, the
    # shim gates on the wrong functions: it would load fine, look active,
    # and protect nothing. Refuse instead.
    ACTUAL_ID="$("${CVE_CC%-gcc}-readelf" -n "$BUILD/rootfs/opt/ch/web_server" 2>/dev/null \
                | awk '/Build ID:/{print $3}')"
    if [ -z "$ACTUAL_ID" ]; then
        echo "ERROR: cannot read the Build ID of $BUILD/rootfs/opt/ch/web_server." >&2
        echo "       The CVE shim's offsets cannot be validated. Refusing to pack." >&2
        exit 1
    fi
    if [ "$ACTUAL_ID" != "$CVE_WEB_SERVER_BUILD_ID" ]; then
        echo "ERROR: web_server Build ID does not match the CVE shim's offsets." >&2
        echo "       expected: $CVE_WEB_SERVER_BUILD_ID" >&2
        echo "       actual:   $ACTUAL_ID" >&2
        echo "       The shim's hard-coded handler addresses (0x501a5 / 0x500ef /" >&2
        echo "       0x500ab) belong to a different build. Shipping it would look" >&2
        echo "       protective while blocking nothing. Re-derive them with" >&2
        echo "       tools/cve_shim/cve_log.c against this binary first." >&2
        exit 1
    fi

    # Run the host-side decision-table test before shipping. This is what
    # catches the failure mode that bit us once already: a comparison written
    # so that GCC proved the whole deny path dead, producing a .so that
    # compiled, loaded, exported the right symbols and denied NOTHING.
    if [ -f "$CVE_TEST_SRC" ]; then
        echo "Running CVE shim decision tests..."
        if cc -O1 -o /tmp/cve_test_deny "$CVE_TEST_SRC" 2>/tmp/cve_test_err.txt \
           && /tmp/cve_test_deny >/tmp/cve_test_out.txt 2>&1; then
            echo "  $(tail -1 /tmp/cve_test_out.txt)"
        else
            echo "ERROR: CVE shim decision tests FAILED -- refusing to pack." >&2
            tail -20 /tmp/cve_test_out.txt >&2 || true
            exit 1
        fi
    fi

    echo "Cross-compiling CVE shim: $SHIM_SRC -> $SHIM_DEST"
    # -fno-stack-protector: the device libc has __stack_chk_fail but NOT
    # __stack_chk_guard, so a protected shim fails to load.
    "$CVE_CC" -O2 -fno-stack-protector -fPIC -shared \
        -o "$SHIM_DEST" "$SHIM_SRC" \
        || { echo "ERROR: CVE shim compile failed -- refusing to pack a stale .so" >&2; exit 1; }
    chmod 755 "$SHIM_DEST"

    # Post-build sanity: the deny path must have SURVIVED compilation. If the
    # compiler folded it away we would ship a no-op. realpath() is only
    # referenced from inside the deny path, so its presence in the dynamic
    # symbol table is a direct proof the logic is live.
    if ! "${CVE_CC%-gcc}-nm" -D "$SHIM_DEST" | grep -q 'realpath'; then
        echo "ERROR: compiled CVE shim does not reference realpath -- the deny" >&2
        echo "       path was optimised away. This is the dead-code failure mode." >&2
        echo "       Refusing to ship a shim that protects nothing." >&2
        exit 1
    fi
    echo "  exports: $("${CVE_CC%-gcc}-nm" -D --defined-only "$SHIM_DEST" | awk '$2=="T"{printf "%s ", $3}')"
    echo "  deny-list entries: $(grep -c '^    "/' tools/cve_shim/deny_logic.h)"
fi

# --- rebuild the login-attempt counter shim -------------------------------
# login_watch.so (opt/ch/login_watch.so) is DETECTION-only. It counts
# unauthenticated login/reset attempts by appending one epoch second per event
# to /tmp (tmpfs). nagios.sh schema 3 turns those into *_5m rates. It never
# blocks, so it cannot lock out the owner.
#
# There are TWO libc variants, because the two cameras differ:
#   glibc (YM500L):  tools/cve_shim/login_watch.c
#       Interposes MsgUserGetPassword only. dlsym is UNUSABLE there (the
#       toolchain mis-binds it to a libc.so.6 that has none), so the real fn
#       is resolved from /proc/self/maps at a fixed libtools offset -> needs
#       the web_server Build-ID guard and forbids any dl* reference.
#   uClibc (YMF46D): tools/cve_shim/login_watch_ymf46d.c
#       libc.so.0 DOES export dlsym, so we resolve via RTLD_NEXT -- no fixed
#       offsets, no Build-ID dependency (this web_server is stripped anyway).
#       Counts MsgUserGetPassword (getuid oracle, CVE-2026-100298) AND
#       MsgSetUserConfig (password reset, CVE-2026-100296).
LW_DEST="$BUILD/rootfs/opt/ch/login_watch.so"

if [ ! -f "$RC_S" ] || ! grep -q '^[[:space:]]*LW_PRELOAD=[^[:space:]]*login_watch' "$RC_S"; then
    echo "login_watch shim: not wired into this tree's rcS -- skipping (opt-in)."
elif [ -e "$BUILD/rootfs/lib/libc.so.0" ]; then
    # ---- uClibc variant (YMF46D) ----
    LW_SRC="tools/cve_shim/login_watch_ymf46d.c"
    if [ ! -f "$LW_SRC" ]; then
        if [ -f "$LW_DEST" ]; then
            echo "WARNING: rcS wants login_watch but $LW_SRC is missing." >&2
            echo "         Packing the EXISTING $LW_DEST unchanged -- it may be STALE." >&2
        else
            echo "WARNING: rcS wants login_watch but neither source nor .so exists." >&2
            echo "         rcS's [ -f ] guard makes this a harmless no-op." >&2
        fi
    elif [ ! -x "${TC_PREFIX}-gcc" ]; then
        echo "ERROR: rcS requires login_watch but the uClibc toolchain is missing." >&2
        exit 1
    else
        # Guard: the two interposed symbols must exist in this libtools.so.
        # If the vendor renamed/moved them, dlsym returns NULL at runtime and
        # the shim fails loud -- but catch it here instead of on the device.
        # Capture nm output first: under `set -o pipefail`, piping straight
        # into `grep -q` makes nm die with SIGPIPE (grep exits on first match),
        # which pipefail reports as a pipeline failure -- a false negative.
        LT_SYMS="$("${TC_PREFIX}-nm" -D --defined-only "$BUILD/rootfs/opt/ch/libtools.so" 2>/dev/null || true)"
        for sym in MsgUserGetPassword MsgSetUserConfig; do
            case "$LT_SYMS" in
                *" T $sym"*) : ;;
                *)
                    echo "ERROR: libtools.so does not export $sym -- the uClibc" >&2
                    echo "       login_watch shim cannot interpose it. Refusing." >&2
                    exit 1 ;;
            esac
        done
        echo "Cross-compiling login_watch shim (uClibc): $LW_SRC -> $LW_DEST"
        "${TC_PREFIX}-gcc" -O2 -fno-stack-protector -fPIC -shared \
            -o "$LW_DEST" "$LW_SRC" -ldl \
            || { echo "ERROR: login_watch compile failed -- refusing to pack a stale .so" >&2; exit 1; }
        chmod 755 "$LW_DEST"
        LW_EXP="$("${TC_PREFIX}-nm" -D --defined-only "$LW_DEST" || true)"
        for sym in MsgUserGetPassword MsgSetUserConfig; do
            case "$LW_EXP" in
                *" T $sym"*) : ;;
                *) echo "ERROR: login_watch does not export $sym -- refusing." >&2; exit 1 ;;
            esac
        done
        echo "  login_watch exports: $(echo "$LW_EXP" | awk '$2=="T"{printf "%s ", $3}')"
    fi
else
    # ---- glibc variant (YM500L) ----
    LW_SRC="tools/cve_shim/login_watch.c"
    if [ ! -f "$LW_SRC" ]; then
        if [ -f "$LW_DEST" ]; then
            echo "WARNING: rcS wants login_watch but $LW_SRC is missing." >&2
            echo "         Packing the EXISTING $LW_DEST unchanged -- it may be STALE." >&2
        else
            echo "WARNING: rcS wants login_watch but neither source nor .so exists." >&2
            echo "         rcS's [ -f ] guard makes this a harmless no-op." >&2
        fi
    else
    LW_CC="${GLIBC_TC:-/home/user/toolchains/armv7-eabihf--glibc--stable-2024.05-1/bin/arm-linux}-gcc"
    if [ ! -x "$LW_CC" ]; then
        LW_CC="/home/user/toolchains/armv7-eabihf--glibc--stable-2024.05-1/bin/arm-buildroot-linux-gnueabihf-gcc"
    fi
    if [ ! -x "$LW_CC" ]; then
        echo "ERROR: rcS requires login_watch but no glibc cross compiler was found." >&2
        exit 1
    fi
    # Build-ID guard: login_watch's libtools offset belongs to this web_server.
    LW_ACTUAL_ID="$("${LW_CC%-gcc}-readelf" -n "$BUILD/rootfs/opt/ch/web_server" 2>/dev/null \
                    | awk '/Build ID:/{print $3}')"
    if [ "$LW_ACTUAL_ID" != "$CVE_WEB_SERVER_BUILD_ID" ]; then
        echo "ERROR: web_server Build ID does not match login_watch's offset." >&2
        echo "       expected: $CVE_WEB_SERVER_BUILD_ID" >&2
        echo "       actual:   $LW_ACTUAL_ID" >&2
        echo "       Re-derive MsgUserGetPassword's offset in login_watch.c first." >&2
        exit 1
    fi
    echo "Cross-compiling login_watch shim: $LW_SRC -> $LW_DEST"
    "$LW_CC" -O2 -fno-stack-protector -fPIC -shared \
        -o "$LW_DEST" "$LW_SRC" \
        || { echo "ERROR: login_watch compile failed -- refusing to pack a stale .so" >&2; exit 1; }
    chmod 755 "$LW_DEST"
    # Post-build sanity: it must export exactly MsgUserGetPassword and pull in
    # nothing but syscall (no dlsym -- device libc.so.6 has none).
    if ! "${LW_CC%-gcc}-nm" -D --defined-only "$LW_DEST" | grep -q ' T MsgUserGetPassword'; then
        echo "ERROR: login_watch does not export MsgUserGetPassword -- refusing." >&2
        exit 1
    fi
    if "${LW_CC%-gcc}-nm" -D --undefined-only "$LW_DEST" | grep -qE 'dlsym|dlvsym|dlopen'; then
        echo "ERROR: login_watch references dl* -- it will fail to load on device." >&2
        exit 1
    fi
    echo "  login_watch exports: $("${LW_CC%-gcc}-nm" -D --defined-only "$LW_DEST" | awk '$2=="T"{printf "%s ", $3}')"
    fi
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
