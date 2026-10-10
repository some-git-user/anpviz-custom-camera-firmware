#!/bin/sh
# Device-side: restart the vendor service tree with the log shim preloaded.
#
# procman (ppid 1) is the supervisor for web_server, mainctrl, media_server,
# record_server, hik_server, rtmp_publish, p2p_server, comm_server,
# h5live_server and dbg_server. LD_PRELOAD must therefore be applied to
# procman so it propagates to every child -- which also means the log shows
# what mainctrl opens, not just web_server. That matters: if mainctrl reads
# /mnt/nand/config.xml for normal operation, denying that path would break
# the camera, and this log is how we find out.
#
# telnetd runs at ppid=1 (reparented to init), so it survives this restart.
# Recovery if this goes wrong: serial console ttyS0 115200, or power-cycle
# (nothing here is written to flash).
LOG=/tmp/cve_log.txt
SHIM=/tmp/cve_log.so

cd /system/opt/ch || exit 1
. /etc/profile 2>/dev/null

echo "=== killing vendor tree ===" >> /tmp/restart.log
PM=$(pidof procman)
for p in $(pidof web_server mainctrl media_server record_server hik_server \
           rtmp_publish p2p_server comm_server h5live_server dbg_server); do
    kill -9 "$p" 2>/dev/null
done
kill -9 $PM 2>/dev/null
sleep 3
# Anything still alive under the old tree, kill again.
for p in $(pidof procman web_server mainctrl); do kill -9 "$p" 2>/dev/null; done
sleep 1

echo "=== restarting procman with preload ===" >> /tmp/restart.log
: > "$LOG"
( LD_PRELOAD="$SHIM" ./procman >> /tmp/procman.log 2>&1 & )
sleep 8
echo "=== after ===" >> /tmp/restart.log
for p in $(ls /proc | grep -E '^[0-9]+$'); do
    c=$(cat /proc/$p/comm 2>/dev/null)
    case "$c" in
        procman|web_server|mainctrl|media_server|record_server|hik_server|\
        rtmp_publish|p2p_server|comm_server|h5live_server|dbg_server)
            echo "$p $c" >> /tmp/restart.log ;;
    esac
done
echo "log lines: $(wc -l < $LOG 2>/dev/null)" >> /tmp/restart.log
echo DONE >> /tmp/restart.log
