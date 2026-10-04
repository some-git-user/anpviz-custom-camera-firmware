#!/usr/bin/env bash
# verify_flash.sh -- did a custom rootfs actually land on a camera?
#
#   ./tools/verify_flash.sh                 # cameras.conf `default`
#   ./tools/verify_flash.sh ym500l        # or a camera key
#   ./tools/verify_flash.sh 192.0.2.11    # or an explicit address
#
# Hosts resolve through tools/cameras.conf (gitignored); nothing is hardcoded.
#
# The vendor web server returns HTTP 200 with the Welcome page for MISSING
# files, so the HTTP status code is worthless. We check three independent
# signals instead, and only trust the canary content.
set -u
here="$(cd "$(dirname "$0")" && pwd)"
HOST="$("$here/cam" "${1:-default}")" || exit 1
CANARY="custom build"

echo "verifying $HOST"
echo

# 1. canary file: must contain our marker, not the Welcome masquerade
body=$(curl -sk --max-time 8 "https://$HOST/CUSTOM_BUILD.txt" 2>/dev/null)
if echo "$body" | grep -qi "Welcome"; then
    c1="FAIL  canary absent (Welcome masquerade) -> rootfs UNCHANGED"
elif echo "$body" | grep -qi "$CANARY"; then
    c1="OK    canary present: $(echo "$body" | head -1)"
else
    c1="WARN  canary unexpected: $(echo "$body" | head -c 80)"
fi
printf "  %s\n" "$c1"

# 2. telnet port state -- INFORMATIONAL ONLY, not a pass/fail signal.
#
# Before custom7 this check hard-FAILED on a closed :23, because our rcS forced
# telnet on via a baked-in /opt/ch/telnet.force_boot marker. That marker is now
# REMOVED: telnet is opt-in via Network -> Service Ports -> Telnet (the spare
# enable_tst attribute), so a CLOSED :23 is the expected default on a healthy
# build and says nothing about whether the rootfs landed.
# Enable it with: the UI checkbox, or `touch /tmp/telnet.force` from an
# existing shell, or rebuild with
# `touch builds/<cam>/rootfs/opt/ch/telnet.force_boot`.
if timeout 3 bash -c "echo > /dev/tcp/$HOST/23" 2>/dev/null; then
    c2="INFO  telnet :23 OPEN (checkbox on, or force marker present)"
else
    c2="INFO  telnet :23 closed (default -- enable via Service Ports -> Telnet)"
fi
printf "  %s\n" "$c2"

# 3. model/identity sanity -- confirms we are talking to the expected camera
info=$(curl -sk --max-time 8 "https://$HOST/cgi-bin/getinfo?type=1" 2>/dev/null)
printf "  INFO  %s\n" "$(echo "$info" | tr -d '\n' | head -c 120)"

# verdict
if echo "$c1" | grep -q "^OK" && echo "$c2" | grep -q "^OK"; then
    echo
    echo "  ==> CUSTOM FIRMWARE IS RUNNING"
    exit 0
else
    echo
    echo "  ==> STILL STOCK -- the update did not apply"
    exit 1
fi
