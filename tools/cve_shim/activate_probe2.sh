#!/bin/sh
# Activate probe_login2.so (MsgUserLogin + getpeername logger) on the clean
# device. Log-only: denies nothing. Answers MsgUserLogin's return convention
# and whether it runs on the getpeername (worker) thread.
# Dev HTTP server serving the .so. Pass it in; never hardcode a LAN address.
HOST=${HOST:?set HOST to the dev http server, e.g. http://HOST:8095}

wget -q -O /tmp/probe_login2.so "$HOST/probe_login2.so" || { echo FETCH_FAILED; exit 1; }
wget -q -O /tmp/probe_login2.so.bytes "$HOST/probe_login2.so.bytes" 2>/dev/null
GOT=$(wc -c < /tmp/probe_login2.so | awk '{print $1}')
WANT=$(awk '{print $1}' /tmp/probe_login2.so.bytes 2>/dev/null)
echo "probe_login2.so got=$GOT want=$WANT"
if [ -n "$WANT" ] && [ "$GOT" != "$WANT" ]; then echo SIZE_MISMATCH; exit 1; fi

if ! mount 2>/dev/null | grep -q '/system/etc'; then
    echo "building overlay /tmp/etcovl5"
    rm -rf /tmp/etcovl5; mkdir -p /tmp/etcovl5
    cp -a /system/etc/. /tmp/etcovl5/ 2>/dev/null || cp -r /system/etc/. /tmp/etcovl5/
    mount --bind /tmp/etcovl5 /system/etc || { echo BIND_FAILED; exit 1; }
fi

printf '/tmp/probe_login2.so\n' > /etc/ld.so.preload
echo "preload now:"; cat /etc/ld.so.preload

rm -f /tmp/probe_login2.txt
kill -9 $(pidof web_server) 2>/dev/null || true
sleep 8
P=$(pidof web_server)
echo "web_server pid $P"
grep -q probe_login2 /proc/$P/maps 2>/dev/null && echo PROBE_ACTIVE || echo PROBE_MISSING
