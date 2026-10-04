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
#
# YM500L NOTE: this model has no Telnet checkbox on the old "Port" tab like the
# YMF46D, but it DOES have a richer "Service Ports" page (StreamingMediaConfig)
# which we extended with a Telnet checkbox writing the same spare enable_tst attr.
# Verified live on .113: /setMediaStreamConfig persists enable_tst, AND a normal
# Service Ports Save PRESERVES it -- the page only setAttribute()s fields it knows
# about, so an attribute it never touches still survives the read-modify-write.
#
# HISTORY: before that checkbox existed we shipped a PERSISTENT override
# (/opt/ch/telnet.force_boot, baked into the squashfs) so telnet was always-on,
# purely to bootstrap shell access on a model with no UI control. That marker is
# REMOVED as of custom7: telnet is now opt-in from the UI, matching YMF46D, and
# we no longer run an always-open telnet listener on the LAN.
# To restore always-on behaviour:
#   touch builds/YM500L/rootfs/opt/ch/telnet.force_boot && ./pack.sh YM500L
enabled() {
	# Manual override: `touch /tmp/telnet.force` forces telnet ON regardless
	# of the persisted config (useful if you ever lock yourself out via the UI).
	[ -e /tmp/telnet.force ] && return 0
	# Build-time always-on escape hatch (see header). Absent by default now.
	[ -e /opt/ch/telnet.force_boot ] && return 0
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
