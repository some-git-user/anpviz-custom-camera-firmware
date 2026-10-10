#!/bin/sh
# ---------------------------------------------------------------------------
# nagios.sh -- redacted monitoring telemetry for Nagios.
#
# Writes /tmp/nagios.txt, served at https://<cam>/nagios.txt via a symlink.
# Deliberately STANDALONE from hwinfo.sh: if this breaks, the web UI diagnostics
# panel keeps working, and vice versa.
#
# Usage:
#   nagios.sh              one-shot, write /tmp/nagios.txt
#   nagios.sh loop [N]     refresh every N seconds (default 10) forever
#
# WHY A SEPARATE REDACTED FEED
# ---------------------------
# hwinfo.txt is unauthenticated (the vendor static handler has no auth at all)
# and carries reconnaissance-grade fields: MAC, IP addresses, gateway, PATH,
# process list, and which busybox applets are missing. That is fine for an
# operator looking at their own page, but wrong for a machine endpoint that a
# monitoring server polls continuously and that may be logged/cached upstream.
#
# This feed carries ONLY what a monitoring check needs. See REDACTED below.
#
# WHY A HEARTBEAT IS MANDATORY
# ---------------------------
# The vendor static handler returns HTTP 200 for a MISSING .txt file
# (Content-Length: 0), and its f404 handler also returns HTTP 200. So the HTTP
# status code CANNOT tell you whether this generator is alive. The heartbeat
# counter and uptime_seconds inside the payload are the only reliable liveness
# signal, and the Nagios plugin must check them.
#
# REDACTED on purpose (present in hwinfo.txt, absent here):
#   mac, ip_addrs, default_route, path, top_processes, cmd_probe, soc_id,
#   machine, cpuinfo, kernel, arch, usb_devices, storage device paths,
#   mtd_devices, rootfs_dev, nand_mount
# None of those are needed to decide "is the camera healthy", and all of them
# help an attacker profile the device.
# ---------------------------------------------------------------------------

OUT=/tmp/nagios.txt
TMP=/tmp/.nagios.$$.tmp
STATE=/tmp/.nagios.state
# schema 2: added the recording-storage (SD/USB) block. Schema 1 had no disk
# metric at all beyond the 1 MB jffs2 config partition.
# schema 3: added login_attempts_5m and pwreset_5m -- brute-force / abuse
# signals for the two unauthenticated endpoints on this model:
#   /cgi-bin/getuid  credential oracle   (CVE-2026-100298)
#   /setUserConfig   admin password reset (CVE-2026-100296)
# Both counted from /tmp logs written by the login_watch.so LD_PRELOAD shim.
# schema 4: added telnet_attempts_5m -- recovery (telnet) login attempts, counted
# from /tmp/telnet_attempts.log written by reclogin.sh (a path the shim can't see).
SCHEMA=4

# The background subshell launched from rcS may not inherit an interactive PATH.
PATH=/bin:/sbin:/usr/bin:/usr/sbin:/opt/ch:$PATH
export PATH

# emit one JSON string field with pure-shell sanitisation.
# No tr/sed: those applets are not compiled into this device's busybox, and a
# missing applet silently empties the pipeline.
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

# emit a raw (unquoted) JSON value -- used for numbers that must parse as numbers
n() {
	v=$1
	k=$2
	[ -z "$v" ] && v=null
	[ "$FIRST" -eq 1 ] || printf ',' >> "$TMP"
	FIRST=0
	printf '"%s":%s' "$k" "$v" >> "$TMP"
}

# first line of a file, or empty (builtin only, no head dependency)
rd() {
	if [ -r "$1" ]; then
		IFS= read -r _line < "$1" 2>/dev/null
		printf '%s' "$_line"
	fi
}

# integer field: keep only digits, else empty
digits() {
	s=$1
	s=${s%%[!0-9]*}
	s=${s##*[!0-9]}
	printf '%s' "$s"
}

# Is $1 a real mount point? The `mountpoint` applet is NOT compiled into this
# busybox, so parse mount instead (same approach hwinfo.sh uses).
mountpoint_ok() {
	mount 2>/dev/null | busybox awk -v m="$1" '$3==m{found=1} END{exit !found}'
}

collect() {
	: > "$TMP"
	FIRST=1
	printf '{' >> "$TMP"

	# --- heartbeat / identity ---------------------------------------------
	# boot_id changes on every boot: lets the checker distinguish "restarted"
	# from "stale generator" without trusting wall-clock agreement.
	_boot=$(rd /proc/sys/kernel/random/boot_id)
	f "$_boot" "boot_id"

	_up=$(rd /proc/uptime)
	_ups=${_up%% *}
	_ups=$(digits "$_ups")
	n "$_ups" "uptime_seconds"

	_now=$(date +%s 2>/dev/null)
	_now=$(digits "$_now")
	n "$_now" "generated_epoch"
	f "$(date '+%Y-%m-%d %H:%M:%S' 2>/dev/null)" "generated_utc"

	# monotonic heartbeat: survives clock jumps, which wall clock does not.
	_seq=0
	if [ -r "$STATE" ]; then
		IFS= read -r _seq < "$STATE" 2>/dev/null
		_seq=$(digits "$_seq")
	fi
	[ -z "$_seq" ] && _seq=0
	_seq=$((_seq + 1))
	printf '%s\n' "$_seq" > "$STATE" 2>/dev/null
	n "$_seq" "heartbeat"

	n "$SCHEMA" "schema"

	# --- temperature ------------------------------------------------------
	# INFINITY6C has no standard thermal_zone; the vendor mstar driver exports
	# the die temperature directly. Bare integer so Nagios can threshold it.
	#
	# !! CALIBRATION IS PER-PLATFORM -- DO NOT "FIX" THRESHOLDS HERE !!
	# This script is shared byte-for-byte between cameras, but the sensors are NOT
	# comparable and neither are the readings:
	#   YMF46D (INFINITY6C, msys/TEMP_R)     ~74 C at normal vendor load.
	#   YM500L (INFINITY3, cpufreq/temp_out) ~88-89 C at rest, 93-96 C when warm.
	# The YM500L sensor tracks real thermal state with a slow time constant, so it
	# stays hot for a while after load. What keeps it hot is that the vendor media
	# pipeline never idles: media_server holds ~45% CPU even with no client
	# connected, so the SoC sits near the top of its normal band permanently.
	# Consequence: the single default pair shipped here (warn 75 / crit 85) is
	# right for YMF46D but puts YM500L in CRITICAL at its NORMAL RESTING state.
	# Set thresholds PER HOST in Nagios (--warn-temp/--crit-temp, e.g. 92/97 for
	# YM500L). Do NOT raise the default in this script -- that would blind
	# YMF46D to real overheating.
	temp=""
	_tr=$(rd /sys/devices/virtual/mstar/msys/TEMP_R 2>/dev/null)
	[ -n "$_tr" ] && temp=$(digits "${_tr##*[!0-9]}")
	if [ -z "$temp" ]; then
		_to=$(rd /sys/devices/system/cpu/cpufreq/temp_out 2>/dev/null)
		[ -n "$_to" ] && temp=$(digits "${_to#Temp=}")
	fi
	if [ -z "$temp" ]; then
		_tz=/sys/class/thermal/thermal_zone0/temp
		if [ -r "$_tz" ]; then
			_raw=$(digits "$(rd $_tz)")
			[ -n "$_raw" ] && temp=$(( _raw / 1000 ))
		fi
	fi
	n "$temp" "temperature_c"

	# --- CPU --------------------------------------------------------------
	# Delta against the previous sample so loop mode needs no extra sleep.
	if [ -r /proc/stat ]; then
		read -r _ u1 n1 s1 i1 w1 q1 sq1 _ < /proc/stat 2>/dev/null
		t1=$((u1 + n1 + s1 + i1 + w1 + q1 + sq1))
		id1=$((i1 + w1))
		if [ -r /tmp/.nagios.cpuprev ]; then
			read -r pt pid < /tmp/.nagios.cpuprev 2>/dev/null
		else
			sleep 1
			pt=$t1
			pid=$id1
		fi
		read -r _ u2 n2 s2 i2 w2 q2 sq2 _ < /proc/stat 2>/dev/null
		t2=$((u2 + n2 + s2 + i2 + w2 + q2 + sq2))
		id2=$((i2 + w2))
		printf '%s %s\n' "$t2" "$id2" > /tmp/.nagios.cpuprev 2>/dev/null
		dt=$((t2 - pt))
		if [ "$dt" -gt 0 ]; then
			cpu=$((( (dt - (id2 - pid)) * 100 ) / dt))
		else
			cpu=0
		fi
		[ "$cpu" -lt 0 ] && cpu=0
		[ "$cpu" -gt 100 ] && cpu=100
		n "$cpu" "cpu_used_pct"
	fi

	# loadavg: first field only
	_la=$(rd /proc/loadavg)
	_la1=${_la%% *}
	n "$(digits "$_la1")" "loadavg_1"

	# --- memory -----------------------------------------------------------
	if [ -r /proc/meminfo ]; then
		mt=$(grep -m1 MemTotal: /proc/meminfo | busybox awk '{print $2}')
		ma=$(grep -m1 MemAvailable: /proc/meminfo | busybox awk '{print $2}')
		mt=$(digits "$mt")
		ma=$(digits "$ma")
		n "$mt" "mem_total_kb"
		n "$ma" "mem_avail_kb"
		if [ -n "$mt" ] && [ -n "$ma" ] && [ "$mt" -gt 0 ]; then
			n "$(( (mt - ma) * 100 / mt ))" "mem_used_pct"
		else
			n "" "mem_used_pct"
		fi
	fi

	# --- config partition (the only writable storage that matters) ---------
	# jffs2 /mnt/nand holds config.xml; running full breaks configuration
	# persistence, so this is a first-class check.
	_nand_pct=""
	_nand_avail=""
_df=$(df -k /mnt/nand 2>/dev/null | busybox awk 'NR==2 {print $4" "$5}')
	if [ -n "$_df" ]; then
		_nand_avail=$(digits "$(echo "$_df" | busybox awk '{print $1}')")
		_nand_pct=$(digits "$(echo "$_df" | busybox awk '{print $2}' | busybox sed 's/%//')")
	fi
	n "$_nand_pct" "nand_used_pct"
	n "$_nand_avail" "nand_avail_kb"

	# --- RECORDING STORAGE (SD card / USB) --------------------------------
	# This is the disk metric that actually matters on a dashcam: the volume
	# video is written to. Schema 1 reported only the 1 MB jffs2 config
	# partition above, so a FULL OR MISSING recording card was completely
	# invisible to monitoring -- the single most likely storage failure on
	# this device class.
	#
	# Slot preference: mmc0 (primary recorder) then mmc1 then usb. We report
	# the SLOT LABEL, never the device node or mount path, to stay redacted.
	_rec_slot=""
	_rec_mount=""
	for pair in "mmc0:/mnt/mmc0" "mmc1:/mnt/mmc1" "usb:/mnt/usb"; do
		_slot=${pair%%:*}
		_m=${pair#*:}
		if mountpoint_ok "$_m"; then
			_rec_slot="$_slot"
			_rec_mount="$_m"
			break
		fi
	done

	if [ -n "$_rec_slot" ]; then
		n 1 "rec_storage_present"
		f "$_rec_slot" "rec_storage_slot"
		# df -k cols: 1K-blocks used available use%
	_rd=$(df -k "$_rec_mount" 2>/dev/null | busybox awk 'NR==2 {print $2" "$3" "$4" "$5}')
		_r_total=""; _r_used=""; _r_avail=""; _r_pct=""
		if [ -n "$_rd" ]; then
			_r_total=$(digits "$(echo "$_rd" | busybox awk '{print $1}')")
			_r_used=$(digits "$(echo "$_rd" | busybox awk '{print $2}')")
			_r_avail=$(digits "$(echo "$_rd" | busybox awk '{print $3}')")
			_r_pct=$(digits "$(echo "$_rd" | busybox awk '{print $4}' | busybox sed 's/%//')")
		fi
		n "$_r_total" "rec_storage_total_kb"
		n "$_r_used" "rec_storage_used_kb"
		n "$_r_avail" "rec_storage_avail_kb"
		n "$_r_pct" "rec_storage_used_pct"
	else
		# No recording volume mounted. Emit explicit nulls so the checker can
		# tell "no card" apart from "card present but metric unreadable".
		n 0 "rec_storage_present"
		f "none" "rec_storage_slot"
		n "" "rec_storage_total_kb"
		n "" "rec_storage_used_kb"
		n "" "rec_storage_avail_kb"
		n "" "rec_storage_used_pct"
	fi

	# --- process liveness -------------------------------------------------
	# Count processes, and confirm the two things we actually care about exist:
	# the web server and the watchdog. Reported as booleans, not names/paths.
	_pcount=$(ps 2>/dev/null | wc -l)
	n "$(digits "$_pcount")" "process_count"
	if ps 2>/dev/null | grep -q '[w]eb_server'; then
		_web=1
	else
		_web=0
	fi

	# Watchdog: do NOT just grep for a process name -- the two cameras differ:
	#   YMF46D  -> userspace-style kernel thread named [watchdogd]
	#   YM500L  -> per-CPU kernel thread [watchdog/0], NO watchdogd at all
	# A name match would false-negative on YM500L. What actually matters is
	# whether /dev/watchdog is HELD OPEN by a process, i.e. someone armed it
	# and is petting it (YMF46D: mainctrl; YM500L: main). fuser is not
	# available on YMF46D, so scan /proc/*/fd with plain ls instead.
	_wd=0
	if [ -e /dev/watchdog ]; then
		for _p in /proc/[0-9]*; do
			if ls -l "$_p/fd" 2>/dev/null | grep -q watchdog; then
				_wd=1
				break
			fi
		done
	fi
	n "$_web" "web_server_running"
	n "$_wd" "watchdog_running"

	# --- login-attempt + password-reset rates (abuse signals) ---------------
	# /tmp/login_attempts.log and /tmp/pwreset.log are one epoch second per
	# event, appended by login_watch.so. Count events in the last 300 s. An
	# absent file (shim not loaded) -> null, so the checker can tell "no shim"
	# from "shim, zero events". These are GLOBAL counts: the endpoints expose
	# no client IP at any interposable layer, so per-source attribution is not
	# possible. Detection only -- the shim never blocks, so the owner cannot be
	# locked out.
	_login=""
	if [ -r /tmp/login_attempts.log ]; then
		_cut=$(( _now - 300 ))
		_login=$(busybox awk -v c="$_cut" '
			$1+0 >= c { n++ }
			END { print n+0 }' /tmp/login_attempts.log 2>/dev/null)
		_login=$(digits "$_login")
	fi
	n "$_login" "login_attempts_5m"

	_pwreset=""
	if [ -r /tmp/pwreset.log ]; then
		_cut=$(( _now - 300 ))
		_pwreset=$(busybox awk -v c="$_cut" '
			$1+0 >= c { n++ }
			END { print n+0 }' /tmp/pwreset.log 2>/dev/null)
		_pwreset=$(digits "$_pwreset")
	fi
	n "$_pwreset" "pwreset_5m"

	# --- telnet recovery-login rate ---------------------------------------
	# /tmp/telnet_attempts.log is one epoch second per recovery (telnet) login
	# attempt, appended by reclogin.sh. That path never touches web_server, so
	# login_watch.so cannot see it. Absent file -> null. Detection only.
	_telnet=""
	if [ -r /tmp/telnet_attempts.log ]; then
		_cut=$(( _now - 300 ))
		_telnet=$(busybox awk -v c="$_cut" '
			$1+0 >= c { n++ }
			END { print n+0 }' /tmp/telnet_attempts.log 2>/dev/null)
		_telnet=$(digits "$_telnet")
	fi
	n "$_telnet" "telnet_attempts_5m"

	printf '}\n' >> "$TMP"

	# Atomic replace: a reader must never observe a half-written file.
	mv "$TMP" "$OUT" 2>/dev/null || { cat "$TMP" > "$OUT"; rm -f "$TMP"; }
}

case "$1" in
	loop)
		interval=${2:-10}
		while :; do
			collect
			sleep "$interval"
		done
		;;
	*)
		collect
		;;
esac
