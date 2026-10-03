#!/usr/bin/env bash
# Build the Nagios CGI auth shim and install it into the YMF46D build tree.
#
#   ./build_shim.sh [slug]      (default slug: YMF46D)
#
# Requires the Bootlin ARMv7 hard-float uClibc toolchain. Override TC_PREFIX if
# yours differs. The shim ABI is device-specific (ARMv7 VFPv3-D16 hard-float,
# uClibc 1.0.31) -- see repo memory anjoy-cgi-shim.md before changing target.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
cd "$HERE"

SLUG="${1:-YMF46D}"
TC_PREFIX="${TC_PREFIX:-/home/user/toolchains/armv7-eabihf--uclibc--stable-2024.05-1/bin/arm-buildroot-linux-uclibcgnueabihf}"
CC="${TC_PREFIX}-gcc"
DEST="$HERE/../../builds/${SLUG}/rootfs/opt/ch/nagios_authd.so"
[ -x "$CC" ] || { echo "toolchain not found: $CC" >&2; echo "set TC_PREFIX=..." >&2; exit 1; }

echo "Compiling nagios_authd.c -> $DEST"
"$CC" -O2 -fPIC -shared -o nagios_authd.so nagios_authd.c
cp -f nagios_authd.so "$DEST"
chmod 755 "$DEST"

echo "Exports:"
"${TC_PREFIX}-nm" -D --defined-only "$DEST" | grep -E 'http_cgi_find|http_cgi_handle' || true
echo "Installed: $DEST"
echo "Now run:  ./pack.sh ${SLUG}  to bake it into a flashable image."
