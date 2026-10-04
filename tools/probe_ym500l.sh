#!/bin/sh
# probe.sh -- map the YM500L runtime layout (run from /tmp on the device)
echo "=== / listing (symlinks visible) ==="
ls -la / 2>/dev/null
echo
echo "=== where does busybox resolve? ==="
echo "PATH=$PATH"
for d in /config /sbin /system/sbin /system/bin /vendor/bin /ext/bin /bin /usr/bin; do
    if [ -e "$d/busybox" ]; then
        printf "  %-16s %s applets\n" "$d/busybox" "$($d/busybox --list 2>/dev/null | wc -l)"
    fi
done
echo
echo "=== /opt vs /system/opt ==="
ls -ld /opt 2>/dev/null
ls -ld /system/opt 2>/dev/null
ls -ld /opt/ch 2>/dev/null
ls -ld /system/opt/ch 2>/dev/null
echo
echo "=== our files: which path is real? ==="
ls -la /opt/ch/telnetd_ctl.sh 2>/dev/null
ls -la /system/opt/ch/telnetd_ctl.sh 2>/dev/null
echo
echo "=== applets the monitoring scripts need ==="
for a in awk sed grep ps df wc date mount cat tail cut sort uniq printf echo sleep; do
    printf "  %-8s " "$a"
    if busybox --list 2>/dev/null | grep -qx "$a"; then echo YES; else echo "NO  <-- PROBLEM"; fi
done
echo
echo "=== applets we must AVOID (absent) ==="
for a in head tr stat readlink mountpoint nc; do
    printf "  %-12s " "$a"
    if busybox --list 2>/dev/null | grep -qx "$a"; then echo present; else echo ABSENT; fi
done
echo
echo "=== temp sensor candidates ==="
for p in /sys/devices/virtual/mstar/msys/TEMP_R /sys/devices/system/cpu/cpufreq/temp_out /sys/class/thermal/thermal_zone0/temp; do
    printf "  %-56s " "$p"
    cat "$p" 2>/dev/null || echo ABSENT
done
echo
echo "=== recording volume: what is mounted? ==="
grep -iE "mmc|sdcard|usb|storage" /proc/mounts || echo "  (nothing mmc/usb mounted now)"
echo "=== /mnt dirs ==="
ls -la /mnt 2>/dev/null
echo
echo "=== config.xml + enable_tst ==="
ls -la /mnt/nand/config.xml 2>/dev/null
grep -o 'enable_tst="[0-9]*"' /mnt/nand/config.xml 2>/dev/null
echo
echo "=== free space on writable partitions ==="
df -k 2>/dev/null
echo "PROBE_DONE"
