#!/bin/sh
# Activate probe_login.so (accept/getpeername logger) on top of the existing
# /system/etc overlay. Log-only: denies nothing. Used to answer the threading
# question -- does the thread that accept()s a connection also call the login
# handler -- before we build a per-IP rate limiter for /cgi-bin/getuid.
#
# No `tr` (absent on this busybox); use awk. No set -e so a partial step
# still reports instead of vanishing.
# Dev HTTP server serving the .so. Pass it in; never hardcode a LAN address.
HOST=${HOST:?set HOST to the dev http server, e.g. http://HOST:8095}

wget -q -O /tmp/probe_login.so "$HOST/probe_login.so" || { echo FETCH_FAILED; exit 1; }
wget -q -O /tmp/probe_login.so.bytes "$HOST/probe_login.so.bytes" 2>/dev/null
GOT=$(wc -c < /tmp/probe_login.so | awk '{print $1}')
WANT=$(awk '{print $1}' /tmp/probe_login.so.bytes 2>/dev/null)
echo "probe_login.so got=$GOT want=$WANT"
if [ -n "$WANT" ] && [ "$GOT" != "$WANT" ]; then echo SIZE_MISMATCH; exit 1; fi

# The overlay must already be mounted (rw tmpfs at /system/etc). If not, make one.
if ! mount 2>/dev/null | grep -q '/system/etc'; then
    echo "no overlay mounted -- building one at /tmp/etcovl4"
    rm -rf /tmp/etcovl4; mkdir -p /tmp/etcovl4
    cp -a /system/etc/. /tmp/etcovl4/ 2>/dev/null || cp -r /system/etc/. /tmp/etcovl4/
    mount --bind /tmp/etcovl4 /system/etc || { echo BIND_FAILED; exit 1; }
fi

# Preload BOTH the file logger (already there) and the probe. Order: probe first
# so accept/getpeername are ours; cve_log keeps the file-op logging.
printf '/tmp/probe_login.so\n/tmp/cve_log.so\n' > /etc/ld.so.preload
echo "preload now:"; cat /etc/ld.so.preload

rm -f /tmp/probe_login.txt
kill -9 $(pidof web_server) 2>/dev/null || true
sleep 8
P=$(pidof web_server)
echo "web_server pid $P"
grep -q probe_login /proc/$P/maps 2>/dev/null && echo PROBE_ACTIVE || echo PROBE_MISSING
