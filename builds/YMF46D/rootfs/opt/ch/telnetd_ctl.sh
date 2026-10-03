#!/bin/sh
# ---------------------------------------------------------------------------
# telnetd_ctl.sh -- web-controlled telnet daemon (added by custom HTTPS build).
#
# The vendor web_server is a compiled gSOAP binary with NO CGI/exec, so a web
# control cannot launch telnetd directly. But the Port tab's SOAP round-trip
# (/getMediaStreamConfig -> /setMediaStreamConfig) DOES persist KNOWN fields of
# the <StreamAccess> node to /mnt/nand/config.xml (custom attributes are dropped
# by the server's fixed-struct serializer).
#
# We piggyback on the spare field enable_tst (parsed by libtools.so but consumed
# by NO feature and exposed in NO UI -- verified). The web UI "Telnet" checkbox
# sets enable_tst="1"/"0". This daemon polls that value and starts/stops telnetd.
#
# Login is handled by /opt/ch/reclogin.sh (fixed creds, immune to the vendor
# mainctrl password overwrite). See rcS.
#
# Default: telnet DISABLED (enable_tst defaults to 0 in config.default).
# Enable via: Configuration -> Network -> Port -> Telnet -> Confirm.
# ---------------------------------------------------------------------------

CFG=/mnt/nand/config.xml
LOGIN=/opt/ch/reclogin.sh
POLL=${1:-5}

# Survive the controlling-terminal teardown when this daemon (started from a
# telnet session during testing) kills telnetd and drops its own login shell.
trap '' HUP

# Read the enable_tst value from the persisted config. Pure-shell, no tr/cut
# (those applets are not compiled into this busybox).
enabled() {
	# Manual override: `touch /tmp/telnet.force` forces telnet ON regardless
	# of the persisted config (useful if you ever lock yourself out via the UI).
	[ -e /tmp/telnet.force ] && return 0
	[ -r "$CFG" ] || return 1
	# find the enable_tst="N" attribute and extract N
	while IFS= read -r line; do
		case "$line" in
			*enable_tst=*)
				v=${line#*enable_tst=\"}
				v=${v%%\"*}
				[ "$v" = "1" ] && return 0 || return 1
				;;
		esac
	done < "$CFG"
	return 1
}

# Match the real telnetd binary but NOT this telnetd_ctl.sh daemon. The daemon
# shows up as "sh /tmp/telnetd_ctl.sh" which also contains the substring
# "telnetd", so we exclude anything containing "_ctl".
telnetd_pids() {
	ps 2>/dev/null | grep '[t]elnetd' | grep -v '_ctl' | awk '{print $1}'
}

running() {
	[ -n "$(telnetd_pids)" ]
}

start_telnetd() {
	if [ -x "$LOGIN" ]; then
		telnetd -l "$LOGIN" &
	else
		telnetd &
	fi
	echo "TELNET: enabled via web config (enable_tst=1)" > /dev/console
}

stop_telnetd() {
	# kill any running telnetd (telnetd_pids excludes this _ctl daemon)
	for p in $(telnetd_pids); do
		kill "$p" 2>/dev/null
		kill -9 "$p" 2>/dev/null
	done
	echo "TELNET: disabled via web config (enable_tst=0)" > /dev/console
}

# Initial sync at boot.
if enabled; then
	start_telnetd
fi

# Poll forever.
while true; do
	sleep "$POLL"
	if enabled; then
		running || start_telnetd
	else
		running && stop_telnetd
	fi
done
