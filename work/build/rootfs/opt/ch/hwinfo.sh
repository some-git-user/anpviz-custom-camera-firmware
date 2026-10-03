#!/bin/sh
# ---------------------------------------------------------------------------
# hwinfo.sh -- hardware telemetry collector for the web UI "version" page.
#
# Writes /tmp/hwinfo.json (served at http(s)://<cam>/hwinfo.json via a symlink).
# Every read is guarded: a missing node yields "n/a" so the page never breaks.
#
# Usage:
#   hwinfo.sh            one-shot, write /tmp/hwinfo.json
#   hwinfo.sh loop [N]   refresh every N seconds (default 5) forever
#
# Added by the custom HTTPS build. Remove the rcS hook + this file to revert.
# ---------------------------------------------------------------------------

# NOTE: served as .txt, NOT .json -- the vendor web_server has no .json
# content-type and would fall through to its f404 handler. Content is still JSON.
OUT=/tmp/hwinfo.txt
TMP=/tmp/.hwinfo.$$.tmp
FIRST=1

# The background subshell launched from rcS may NOT inherit the interactive PATH.
# Set it explicitly so external commands (date/grep/awk/...) are always found.
PATH=/bin:/sbin:/usr/bin:/usr/sbin:/opt/ch:$PATH
export PATH
BB=/bin/busybox

# emit one JSON string field:  f <value> <key>
# Sanitise with PURE SHELL BUILTINS only -- no external tr/sed. On this device
# those applets may not be compiled into busybox, and a missing applet makes the
# whole pipeline return empty, turning every value into "n/a" (even $$).
# busybox ash supports ${var//pattern/replacement} and $'\r' etc.
f() {
	v=$1
	k=$2
	v=${v//$'\r'/}
	v=${v//$'\t'/ }
	v=${v//$'\n'/ }
	v=${v//\\/\\\\}
	v=${v//\"/\\\"}
	[ -z "$v" ] && v="n/a"
	[ "$FIRST" -eq 1 ] || printf ',' >> "$TMP"
	FIRST=0
	printf '"%s":"%s"' "$k" "$v" >> "$TMP"
}

# first line of a file, or empty (pure builtin: no head dependency)
rd() {
	if [ -r "$1" ]; then
		IFS= read -r _line < "$1" 2>/dev/null
		printf '%s' "$_line"
	fi
}

# trim trailing spaces using shell builtins only (no sed)
trim() {
	s=$1
	while [ "${s% }" != "$s" ]; do s=${s% }; done
	while [ "${s# }" != "$s" ]; do s=${s# }; done
	printf '%s' "$s"
}

# decode a little-endian hex IPv4 (as in /proc/net/route) to dotted quad.
# Uses ash ${var:off:len} substring -- NO cut/tr (those applets are not
# compiled into this device's busybox).
hex2dec() {
	# $1 = two hex chars -> decimal
	d=0
	i=0
	while [ $i -lt 2 ]; do
		c=${1:$i:1}
		case "$c" in
			0) v=0;; 1) v=1;; 2) v=2;; 3) v=3;; 4) v=4;;
			5) v=5;; 6) v=6;; 7) v=7;; 8) v=8;; 9) v=9;;
			[aA]) v=10;; [bB]) v=11;; [cC]) v=12;; [dD]) v=13;;
			[eE]) v=14;; [fF]) v=15;;
			*) v=0;;
		esac
		d=$(( d * 16 + v ))
		i=$(( i + 1 ))
	done
	printf '%d' "$d"
}
hexip() {
	h=$1
	[ ${#h} -ne 8 ] && { printf '%s' "$h"; return; }
	# little-endian: reverse byte order
	b0=$(hex2dec "${h:6:2}")
	b1=$(hex2dec "${h:4:2}")
	b2=$(hex2dec "${h:2:2}")
	b3=$(hex2dec "${h:0:2}")
	printf '%d.%d.%d.%d' "$b0" "$b1" "$b2" "$b3"
}

collect() {
	: > "$TMP"
	FIRST=1
	printf '{' >> "$TMP"

	# --- self-diagnostics (so the web page reveals env problems) ------------
	f "$$" "pid"
	f "$PATH" "path"
	_dt=$(date '+%Y-%m-%d %H:%M:%S' 2>&1)
	f "$_dt" "date_probe"
	_un=$(uname -r 2>&1)
	f "$_un" "uname_probe"
	_bb=$([ -x "$BB" ] && echo yes || echo no)
	f "$BB:$_bb" "busybox"
	# which applets are ACTUALLY compiled into this busybox? (a symlink existing
	# does NOT mean the applet is built in -- e.g. tr/cut/uniq are missing here).
	# Build the real list from `busybox` output and test membership with grep.
	_have=""
	if [ -x "$BB" ]; then
		"$BB" 2>&1 | busybox awk '/Currently defined/{f=1;next} f' | busybox awk '{gsub(/,/," "); for(i=1;i<=NF;i++) print $i}' > /tmp/.bblist 2>/dev/null
		for _c in date grep awk sed head sort ps df mount lsusb wc uniq tr cut mountpoint; do
			if grep -qx "$_c" /tmp/.bblist 2>/dev/null; then _have="$_have $_c:Y"; else _have="$_have $_c:-"; fi
		done
	fi
	f "$_have" "cmd_probe"

	# --- generated timestamp ------------------------------------------------
	f "$(date '+%Y-%m-%d %H:%M:%S' 2>/dev/null)" "generated"

	# --- SoC / machine ------------------------------------------------------
	f "$(rd /sys/devices/soc0/machine)" "machine"
	f "$(rd /sys/devices/soc0/soc_id)" "soc_id"
	f "$(rd /sys/devices/soc0/family)" "soc_family"
	f "$(grep -m1 -i 'machine\|hardware\|model name' /proc/cpuinfo 2>/dev/null)" "cpuinfo"
	f "$(uname -r 2>/dev/null)" "kernel"
	f "$(uname -m 2>/dev/null)" "arch"
	f "$(nproc 2>/dev/null || grep -c processor /proc/cpuinfo 2>/dev/null)" "cpu_cores"

	# --- CPU load / jiffies -------------------------------------------------
	# /proc/stat  cpu  user nice system idle iowait irq softirq ...
	# Delta is taken against the previous sample stored in /tmp, so loop mode
	# needs no extra sleep. One-shot mode (no prior state) sleeps 1s.
	if [ -r /proc/stat ]; then
		read -r _ u1 n1 s1 i1 w1 q1 sq1 _ < /proc/stat 2>/dev/null
		t1=$((u1 + n1 + s1 + i1 + w1 + q1 + sq1))
		id1=$((i1 + w1))
		if [ -r /tmp/.hwinfo.prev ]; then
			read -r pt pid < /tmp/.hwinfo.prev 2>/dev/null
		else
			# no prior sample: take a 1s baseline so the first page load is real
			sleep 1
			pt=$t1
			pid=$id1
		fi
		read -r _ u2 n2 s2 i2 w2 q2 sq2 _ < /proc/stat 2>/dev/null
		t2=$((u2 + n2 + s2 + i2 + w2 + q2 + sq2))
		id2=$((i2 + w2))
		printf '%s %s\n' "$t2" "$id2" > /tmp/.hwinfo.prev 2>/dev/null
		dt=$((t2 - pt))
		if [ "$dt" -gt 0 ]; then
			cpu=$(( ( (dt - (id2 - pid)) * 100 ) / dt ))
		else
			cpu=0
		fi
		[ "$cpu" -lt 0 ] && cpu=0
		[ "$cpu" -gt 100 ] && cpu=100
		f "$cpu%" "cpu_usage"
		f "idle:$i2 sys:$s2 io:$w2 user:$u2" "cpu_jiffies"
	fi
	f "$(rd /proc/loadavg)" "loadavg"
	f "$(rd /proc/uptime)" "uptime"

	# --- Memory -----------------------------------------------------------
	if [ -r /proc/meminfo ]; then
		mt=$(grep -m1 MemTotal: /proc/meminfo | busybox awk '{print $2}')
		mf=$(grep -m1 MemFree: /proc/meminfo | busybox awk '{print $2}')
		ma=$(grep -m1 MemAvailable: /proc/meminfo | busybox awk '{print $2}')
		buf=$(grep -m1 '^Buffers:' /proc/meminfo | busybox awk '{print $2}')
		cch=$(grep -m1 '^Cached:' /proc/meminfo | busybox awk '{print $2}')
		[ -n "$mt" ] && f "$(( mt / 1024 )) MB (total ${mt} kB)" "mem_total" || f "n/a" "mem_total"
		[ -n "$mf" ] && f "$(( mf / 1024 )) MB (free ${mf} kB)" "mem_free" || f "n/a" "mem_free"
		[ -n "$ma" ] && f "$(( ma / 1024 )) MB (avail ${ma} kB)" "mem_avail" || f "n/a" "mem_avail"
		[ -n "$mt" ] && [ -n "$ma" ] && f "$(( (mt - ma) * 100 / mt ))%" "mem_used_pct" || f "n/a" "mem_used_pct"
		[ -n "$buf" ] && [ -n "$cch" ] && f "$(( (buf + cch) / 1024 )) MB" "mem_buffers_cached" || f "n/a" "mem_buffers_cached"
	fi

	# --- Temperature ------------------------------------------------------
	# This SigmaStar/INFINITY6C SoC exposes NO standard thermal_zone. Instead the
	# vendor mstar driver exports the die temperature directly:
	#   /sys/devices/virtual/mstar/msys/TEMP_R  -> "Temperature 79"
	#   /sys/devices/system/cpu/cpufreq/temp_out -> "Temp=78  VBE=360"
	# Try the native sources first, then fall back to generic thermal zones.
	temp="n/a"
	_tr=$(rd /sys/devices/virtual/mstar/msys/TEMP_R 2>/dev/null)
	if [ -n "$_tr" ]; then
		# strip everything but the trailing integer using ash builtins
		_tc=${_tr##*[!0-9]}
		[ -n "$_tc" ] && temp="$_tc C (SoC die / TEMP_R)"
	fi
	if [ "$temp" = "n/a" ]; then
		_to=$(rd /sys/devices/system/cpu/cpufreq/temp_out 2>/dev/null)
		if [ -n "$_to" ]; then
			_tc=${_to#Temp=}
			_tc=${_tc%%[!0-9]*}
			[ -n "$_tc" ] && temp="$_tc C (cpu temp_out)"
		fi
	fi
	if [ "$temp" = "n/a" ]; then
		for z in /sys/class/thermal/thermal_zone*; do
			if [ -d "$z" ]; then
				tz_type=$(rd "$z/type")
				tz_raw=$(rd "$z/temp")
				if [ -n "$tz_raw" ]; then
					tz_c=$(( tz_raw / 1000 ))
					temp="$tz_c C ($tz_type)"
					break
				fi
			fi
		done
	fi
	f "$temp" "temperature"

	# --- Network / MAC / IP -----------------------------------------------
	mac="n/a"
	for n in eth0 eth1 wlan0 br0; do
		if [ -r "/sys/class/net/$n/address" ]; then
			a=$(rd "/sys/class/net/$n/address")
			[ "$a" != "00:00:00:00:00:00" ] && mac="$a ($n)" && break
		fi
	done
	f "$mac" "mac"
	f "$(trim "$(ifconfig 2>/dev/null | busybox awk '/inet addr:/{split($2,a,":");printf "%s ",a[2]} /inet [0-9]/{printf "%s ",$2}')")" "ip_addrs"
	rt_dev=$(busybox awk 'NR==2{print $1}' /proc/net/route 2>/dev/null)
	rt_gw=$(busybox awk 'NR==2{print $3}' /proc/net/route 2>/dev/null)
	[ -n "$rt_gw" ] && rt_gw=$(hexip "$rt_gw")
	f "${rt_dev:-n/a} gw:${rt_gw:-none}" "default_route"

	# --- Storage: NAND / MTD ----------------------------------------------
	mtd=""
	if [ -r /proc/mtd ]; then
		mtd=$(grep -c mtd /proc/mtd 2>/dev/null)
	fi
	f "$mtd" "mtd_devices"
	# rootfs / overlay / config partitions
	f "$(mount 2>/dev/null | busybox awk '/squashfs/{print $1"@"$3; exit}')" "rootfs_dev"
	f "$(mount 2>/dev/null | busybox awk '/\/mnt\/nand/{print $1" "$3" "$5; exit}')" "nand_mount"

	# --- Storage: SD / USB usage (df) -------------------------------------
	# keys hardcoded (no tr) so they never come out empty
	for pair in "mmc0:/mnt/mmc0" "mmc1:/mnt/mmc1" "usb:/mnt/usb"; do
		key=${pair%%:*}
		m=${pair#*:}
		if mountpoint_ok "$m"; then
			d=$(df -k "$m" 2>/dev/null | busybox awk 'NR==2{print $2" total, "$3" used, "$4" free ("$5")"}')
			f "$d" "storage_$key"
		else
			f "not mounted" "storage_$key"
		fi
	done

	# --- USB devices ------------------------------------------------------
	# lsusb prints one line per device INCLUDING the root hub (this SoC only has
	# the internal EHCI root hub when nothing is plugged in), so use NR>=1.
	_usb=$(lsusb 2>/dev/null | busybox awk '{for(i=1;i<=NF;i++) if($i ~ /^[0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F]:[0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F]$/) {printf "%s ", $i}}')
	[ -z "$_usb" ] && _usb=$(ls /sys/bus/usb/devices/*/idVendor 2>/dev/null | busybox awk '{gsub("/idVendor",""); gsub("/sys/bus/usb/devices/",""); printf "%s ", $0}')
	f "$_usb" "usb_devices"

	# --- Video sensor (SStar mi_sensor proc node) -------------------------
	# The sensor name (e.g. gc4653_MIPI) appears in the mi_sensor0 dump.
	# No cut/tr -- use grep + awk only.
	sensor="$(grep -m1 -oE '[a-zA-Z0-9_]+_MIPI' /proc/mi_modules/mi_sensor/mi_sensor0 2>/dev/null)"
	[ -z "$sensor" ] && sensor="$(grep -m1 -oE 'gc[0-9]+[a-zA-Z_]*|imx[0-9]+[a-zA-Z_]*|os0[0-9]+[a-zA-Z_]*|sc[0-9]+[a-zA-Z_]*' /proc/mi_modules/mi_sensor/mi_sensor0 2>/dev/null)"
	[ -z "$sensor" ] && sensor="$(trim "$(ls /opt/ch/*.ko 2>/dev/null | busybox awk -F/ '{printf "%s ", $NF}')")"
	f "$sensor" "sensor"

	# --- Running processes (most common by name) --------------------------
	# uniq is NOT compiled into this busybox -> count with awk (tab-delimited
	# so names containing spaces survive), sort by count desc, format.
	f "$(ps -o comm 2>/dev/null | busybox awk '{c[$0]++} END{for(k in c) printf "%d\t%s\n", c[k], k}' 2>/dev/null | sort -rn 2>/dev/null | head -8 | busybox awk -F'\t' '{printf "%dx%s; ", $1, $2}')" "top_processes"
	f "$(ps 2>/dev/null | busybox awk 'END{print NR-1}')" "process_count"

	printf '}\n' >> "$TMP"
	mv -f "$TMP" "$OUT"
}

# mountpoint check without depending on the mountpoint applet
mountpoint_ok() {
	mount 2>/dev/null | busybox awk -v m="$1" '$3==m{found=1} END{exit !found}'
}

# --- entrypoint ---------------------------------------------------------------
case "$1" in
	loop)
		interval=${2:-5}
		while true; do
			collect
			sleep "$interval"
		done
		;;
	*)
		collect
		;;
esac
