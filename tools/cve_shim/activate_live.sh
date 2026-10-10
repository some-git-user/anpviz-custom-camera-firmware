#!/bin/sh
# Device-side: activate cve_deny.so on the LIVE camera without reflashing and
# without restarting procman.
#
# WHY THIS SHAPE
# /etc is a symlink into the read-only squashfs at /system/etc, so we cannot
# simply write /etc/ld.so.preload. We build a writable copy of /etc in tmpfs,
# add ld.so.preload to it, and bind-mount it over /system/etc. glibc reads
# /etc/ld.so.preload at exec time, so any process started after the bind gets
# the shim.
#
# cp -a (not symlinks) is REQUIRED. An earlier attempt used
#   ln -s /system/etc/$f $ovl/$f
# which silently replaced the real "passwd -> /tmp/passwd" symlink with
# "passwd -> /system/etc/passwd". That changes the very path topology the
# shim is designed around, so the test would have been measuring nothing.
#
# web_server is restarted by killing it alone: procman respawns it within a
# few seconds and the reboot watchdog belongs to mainctrl, which we do NOT
# touch. Killing procman or mainctrl trips the watchdog and hard-reboots.
set -e

# Dev HTTP server serving the .so. Pass it in; never hardcode a LAN address.
HOST=${HOST:?set HOST to the dev http server, e.g. http://HOST:8095}
SHIM_URL=$HOST/cve_deny.so
OVL=/tmp/etcovl

echo "== fetch shim =="
cd /tmp
wget -q -O /tmp/cve_deny.so "$SHIM_URL" || { echo "FETCH_FAILED"; exit 1; }
ls -l /tmp/cve_deny.so

echo "== build /etc overlay =="
rm -rf "$OVL"
mkdir -p "$OVL"
cp -a /system/etc/. "$OVL"/ 2>/dev/null || cp -r /system/etc/. "$OVL"/
printf '/tmp/cve_deny.so\n' > "$OVL/ld.so.preload"
# The real passwd symlink must survive cp -a; assert it.
ls -l "$OVL/passwd"

echo "== bind over /system/etc =="
umount /system/etc 2>/dev/null || true
mount --bind "$OVL" /system/etc
echo "preload now: $(cat /etc/ld.so.preload)"
ls -l /etc/passwd

echo "== restart web_server only (procman respawns it) =="
kill -9 $(pidof web_server) 2>/dev/null || true
sleep 8
WP=$(pidof web_server)
echo "web_server pid: $WP"
if [ -n "$WP" ]; then
    if grep -q cve_deny /proc/$WP/maps; then
        echo "PRELOAD_ACTIVE"
    else
        echo "PRELOAD_MISSING"
        grep -c ld.so /proc/$WP/maps 2>/dev/null || true
    fi
else
    echo "WEB_SERVER_GONE"
fi
echo DONE
