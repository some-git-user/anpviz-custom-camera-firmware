#!/bin/sh
# Device-side: activate egress_log.so (LOG ONLY) on the live camera to learn
# the real outbound-connection set before writing any SSRF deny policy.
#
# Same /etc-overlay technique as activate_live.sh (see that file for why:
# /etc is a symlink into read-only squashfs, and cp -a is required so the
# real "passwd -> /tmp/passwd" symlink topology survives).
#
# cve_deny.so is ALREADY flashed and loaded via rcS. We ADD egress_log.so on
# top of it via ld.so.preload; both are active. egress_log.so forwards every
# connect() unconditionally -- it cannot break anything -- and records
#   connect|<dst-ip:port>|ra=0x<caller>
# The ra tells us WHICH code path made each connection, so we can tell the
# connect_check SSRF handler apart from legitimate NTP / P2P / DDNS egress.
set -e

# Dev HTTP server serving the .so. Pass it in; never hardcode a LAN address.
HOST=${HOST:?set HOST to the dev http server, e.g. http://HOST:8095}
OVL=/tmp/etcovl

echo "== fetch egress logger =="
wget -q -O /tmp/egress_log.so "$HOST/egress_log.so" || { echo "FETCH_FAILED"; exit 1; }
ls -l /tmp/egress_log.so
# INTEGRITY GATE. A truncated download that lands in ld.so.preload makes EVERY
# new process die with "file too short" + Bus error -- including the telnet
# helpers we need to fix it. Verify the size matches what the server has
# before touching the preload. (This bit us: the http server was restarted
# between listing and fetching, wget wrote a partial file, and the box went
# bus-error on every exec.)
# busybox on this device has NO `tr` applet -- use awk to strip whitespace
# from wc output. (An earlier `tr -d ' '` here died under set -e and the
# whole gate silently skipped, which is worse than having no gate.)
EXPECT_BYTES=$(wget -q -O - "$HOST/egress_log.so.bytes" 2>/dev/null | awk '{print $1}')
if [ -n "$EXPECT_BYTES" ]; then
    GOT_BYTES=$(wc -c < /tmp/egress_log.so 2>/dev/null | awk '{print $1}')
    if [ "$GOT_BYTES" != "$EXPECT_BYTES" ]; then
        echo "SIZE_MISMATCH got=$GOT_BYTES want=$EXPECT_BYTES -- NOT activating."
        rm -f /tmp/egress_log.so
        exit 1
    fi
    echo "size OK ($GOT_BYTES bytes)"
fi

echo "== build /etc overlay with BOTH shims =="
rm -rf "$OVL"
mkdir -p "$OVL"
cp -a /system/etc/. "$OVL"/ 2>/dev/null || cp -r /system/etc/. "$OVL"/
# Order: egress_log first so its connect() is the one that logs; cve_deny
# still owns the file primitives. Both stay loaded.
printf '/tmp/egress_log.so\n/system/opt/ch/cve_deny.so\n' > "$OVL/ld.so.preload"
ls -l "$OVL/passwd"

echo "== bind over /system/etc =="
umount /system/etc 2>/dev/null || true
mount --bind "$OVL" /system/etc
echo "preload now: $(cat /etc/ld.so.preload | tr '\n' ' ')"

echo "== restart web_server only (procman respawns it) =="
rm -f /tmp/egress_log.txt
kill -9 $(pidof web_server) 2>/dev/null || true
sleep 8
WP=$(pidof web_server)
echo "web_server pid: $WP"
if [ -n "$WP" ]; then
    E=$(grep -c egress_log /proc/$WP/maps 2>/dev/null || echo 0)
    C=$(grep -c cve_deny /proc/$WP/maps 2>/dev/null || echo 0)
    echo "egress_log mappings: $E   cve_deny mappings: $C"
    [ "$E" -gt 0 ] && echo "EGRESS_LOG_ACTIVE" || echo "EGRESS_LOG_MISSING"
else
    echo "WEB_SERVER_GONE"
fi
echo DONE
