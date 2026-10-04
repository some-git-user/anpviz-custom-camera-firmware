#!/usr/bin/env bash
# verify_flash.sh -- did a custom rootfs actually land on a camera?
#
#   ./tools/verify_flash.sh                 # defaults to YM500L .113
#   ./tools/verify_flash.sh 192.0.2.10
#
# The vendor web server returns HTTP 200 with the Welcome page for MISSING
# files, so the HTTP status code is worthless. We check three independent
# signals instead, and only trust the canary content.
set -u
HOST="${1:-192.0.2.11}"
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

# 2. telnet must be open (our rcS opens it via telnet.force_boot)
if timeout 3 bash -c "echo > /dev/tcp/$HOST/23" 2>/dev/null; then
    c2="OK    telnet :23 OPEN (our rcS ran)"
else
    c2="FAIL  telnet :23 CLOSED (our rcS did not run)"
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
