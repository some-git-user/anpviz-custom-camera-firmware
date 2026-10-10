#!/bin/sh
# ---------------------------------------------------------------------------
# reclogin.sh -- telnet login wrapper (added by custom build).
#
# busybox telnetd is started with:  telnetd -l /opt/ch/reclogin.sh
# so this script IS the login program: the telnet socket is stdin/stdout/stderr.
#
# It accepts a fixed recovery account and then hands over an interactive shell.
# This bypasses /etc/passwd entirely, so it keeps working even though the
# vendor mainctrl overwrites the root password at boot (it runs
#   echo -e "<pw>\n<pw>" | passwd root
# when /opt/ch/flag.set.passwd is present).
#
# The password is NOT hardcoded here. It is read from a separate file that is
# generated at repack time by pack.sh and is NOT committed to git:
#     /opt/ch/reclogin.pass     (single line: the recovery password)
# Override the file location with RECLOGIN_PASS_FILE=... .
#
# Recovery login is always: root
# Recovery password: see the value printed by ./pack.sh (or RECOVERY_PASS env).
#
# To disable telnet entirely: remove the telnetd line in rcS (or leave
# enable_tst=0 so the web-controlled daemon never starts it).
# ---------------------------------------------------------------------------

USER=root
PASS_FILE="${RECLOGIN_PASS_FILE:-/opt/ch/reclogin.pass}"

if [ -r "$PASS_FILE" ]; then
        # first line of the file is the password; strip trailing CR/LF
        IFS= read -r PASS < "$PASS_FILE" 2>/dev/null
        PASS=${PASS%$'\r'}
else
        PASS=""
fi

# No password configured -> refuse login (fail closed).
if [ -z "$PASS" ]; then
        printf 'Recovery login unavailable (no password file).\r\n'
        exit 1
fi

PATH=/bin:/sbin:/usr/bin:/usr/sbin:/opt/ch:$PATH
export PATH

# Recover the peer IP of this telnet session. busybox 1.24 telnetd gives the
# login program NO peer info: it passes no argv, sets no REMOTEHOST/REMOTEIP, and
# our fd 0 is a pty (/dev/pts/N), not the socket. The socket lives one level up:
# telnetd forks a child per connection and that child holds exactly one
# ESTABLISHED socket (the client). So we list the parent's socket inodes and pick
# the ESTABLISHED (st==01) one from /proc/net/tcp, decoding the little-endian hex
# peer address. Verified on-device (.109): resolves the real client IP. Returns
# non-zero (empty) if the lookup fails -- callers treat that as "unknown" and
# NEVER as a reason to deny a login (fail-open; owner cannot be locked out).
# NOTE: readlink/tr/od are NOT compiled into this busybox -- use ls + awk only.
peer_ip() {
	_p=$PPID
	[ -d "/proc/$_p/fd" ] || return 1
	_inos=$(ls -l /proc/$_p/fd 2>/dev/null | busybox awk '
		match($0, /socket:\[[0-9]+\]/) { print substr($0, RSTART+8, RLENGTH-9) }')
	[ -n "$_inos" ] || return 1
	busybox awk -v inos="$_inos" '
		BEGIN { hd="0123456789ABCDEF"; for (n=0;n<16;n++) H[substr(hd,n+1,1)]=n
			m=split(inos, arr, "\n"); for (k=1;k<=m;k++) want[arr[k]]=1 }
		function hx(s) { return H[substr(s,1,1)]*16 + H[substr(s,2,1)] }
		$4=="01" && ($10 in want) { split($3,a,":"); h=a[1]
			printf "%d.%d.%d.%d\n", hx(substr(h,7,2)),hx(substr(h,5,2)),hx(substr(h,3,2)),hx(substr(h,1,2)); exit }
	' /proc/net/tcp 2>/dev/null
}

# best-effort terminal setup (may fail on a raw socket, that's fine)
stty echo 2>/dev/null
stty icanon 2>/dev/null

printf 'Recovery login (%s): ' "$USER"
read login
# turn echo off for the password if possible
stty -echo 2>/dev/null
printf 'Password: '
read pass
stty echo 2>/dev/null
printf '\r\n'

# Count this attempt (success OR failure) for brute-force detection.
# /tmp is tmpfs; nagios.sh schema 4 turns this into telnet_attempts_5m. This
# is the telnet path, which does NOT go through web_server's MsgUserGetPassword,
# so login_watch.so cannot see it -- the counter has to live here instead.
#
# The epoch log stays IP-free on purpose: it is the source for the Nagios feed,
# which is deliberately redacted (no client addresses leave the device). The
# source IP goes to a SEPARATE local-only log, /tmp/telnet_access.log, that the
# owner reads over serial/telnet -- attribution without leaking IPs to the poller.
date +%s >> /tmp/telnet_attempts.log 2>/dev/null

if [ "$login" = "$USER" ] && [ "$pass" = "$PASS" ]; then
	_result=OK
else
	_result=BAD
fi
_ip=$(peer_ip) || _ip=unknown
printf '%s %s %s\n' "$(date +%s)" "$_result" "$_ip" >> /tmp/telnet_access.log 2>/dev/null

if [ "$_result" = OK ]; then
	printf 'Login OK\r\n'
	# give a proper interactive shell on the telnet socket
	exec /bin/sh -l
fi

printf 'Login incorrect\r\n'
exit 1
