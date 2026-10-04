#!/usr/bin/env bash
# verify_flash.sh -- did a custom rootfs actually land on a camera?
#
#   ./tools/verify_flash.sh 192.0.2.11
#   ./tools/verify_flash.sh              # prompts for the address
#   CAM_IP=192.0.2.11 ./tools/verify_flash.sh
#
# The vendor web server returns HTTP 200 with the Welcome page for MISSING
# files, so the HTTP status code is worthless. What decides is the canary file's
# contents. The telnet port and the identity blob are printed alongside for
# context, not as pass/fail checks.
set -u
here="$(cd "$(dirname "$0")" && pwd)"
. "$here/cam"
HOST="$(cam_host "${1:-}" "camera IP to verify")" || exit 1
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
# Telnet is opt-in via Network -> Service Ports -> Telnet (the spare
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

# verdict -- the canary is the only thing that decides. c2 is informational and
# deliberately not part of this test.
echo
case "$c1" in
    OK*)
        echo "  ==> CUSTOM FIRMWARE IS RUNNING"
        exit 0
        ;;
    FAIL*)
        echo "  ==> STILL STOCK -- the update did not apply"
        exit 1
        ;;
    *)
        echo "  ==> UNCLEAR -- canary exists but does not look like ours."
        echo "      Read the output above before trusting either way."
        exit 2
        ;;
esac
