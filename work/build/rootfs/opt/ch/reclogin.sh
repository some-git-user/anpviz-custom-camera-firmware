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
# Recovery credentials:
#     login: root
#     password: REDACTED_RECOVERY_PASSWORD
#
# To change: edit USER / PASS below. To disable: remove the telnetd line in rcS.
# ---------------------------------------------------------------------------

USER=root
PASS='REDACTED_RECOVERY_PASSWORD'

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

if [ "$login" = "$USER" ] && [ "$pass" = "$PASS" ]; then
	printf 'Login OK\r\n'
	# give a proper interactive shell on the telnet socket
	exec /bin/sh -l
fi

printf 'Login incorrect\r\n'
exit 1
