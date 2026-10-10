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
date +%s >> /tmp/telnet_attempts.log 2>/dev/null

if [ "$login" = "$USER" ] && [ "$pass" = "$PASS" ]; then
	printf 'Login OK\r\n'
	# give a proper interactive shell on the telnet socket
	exec /bin/sh -l
fi

printf 'Login incorrect\r\n'
exit 1
