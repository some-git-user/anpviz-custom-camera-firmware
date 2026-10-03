#!/usr/bin/env python3
"""check_anjoy_nagios.py -- Nagios plugin for the Anjoy888 camera monitoring feed.

Polls https://<cam>/nagios.txt (a redacted JSON telemetry feed) and returns
Nagios exit codes with perfdata.

WHY THIS IS NOT JUST `check_http`
-------------------------------
The camera's vendor web_server returns **HTTP 200 for a missing .txt file**
(Content-Length: 0), and its f404 handler also returns 200. So the HTTP status
code carries no information about whether the on-device generator is alive.
A naive check_http would report OK forever after the generator died.

Therefore liveness is derived from the payload itself: we keep server-side state
recording the last heartbeat and boot_id we saw, and compare.

  heartbeat advanced            -> generator alive
  heartbeat unchanged, < window -> still OK (poll was too soon)
  heartbeat unchanged, > window -> CRITICAL (generator dead)
  boot_id changed               -> device rebooted (report, and it's OK)

Usage:
  check_anjoy_nagios.py --host 192.0.2.10 [--no-tls] \
      --state-file /var/tmp/check_anjoy_109.json \
      --stale 90 --warn-temp 75 --crit-temp 85 \
      --warn-cpu 85 --crit-cpu 95 \
      --warn-mem 85 --crit-mem 95 \
      --warn-nand 80 --crit-nand 92

Exit codes: 0 OK, 1 WARNING, 2 CRITICAL, 3 UNKNOWN.
"""

import argparse
import json
import os
import ssl
import sys
import tempfile
import time
import urllib.error
import urllib.request

OK, WARNING, CRITICAL, UNKNOWN = 0, 1, 2, 3

STATUS_NAME = {OK: "OK", WARNING: "WARNING", CRITICAL: "CRITICAL", UNKNOWN: "UNKNOWN"}


def parse_args():
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--host", required=True, help="camera address")
    p.add_argument("--port", type=int, default=None)
    p.add_argument("--path", default="/nagios.txt")
    p.add_argument("--no-tls", action="store_true",
                   help="use http:// instead of https://")
    p.add_argument("--timeout", type=float, default=10.0)
    p.add_argument("--state-file", default=None,
                   help="path to persist last heartbeat/boot_id "
                        "(default: /tmp/check_anjoy_<host>.json)")
    p.add_argument("--stale", type=float, default=90.0,
                   help="seconds without a heartbeat advance before CRITICAL")

    p.add_argument("--warn-temp", type=float, default=75.0)
    p.add_argument("--crit-temp", type=float, default=85.0)
    p.add_argument("--warn-cpu", type=float, default=85.0)
    p.add_argument("--crit-cpu", type=float, default=95.0)
    p.add_argument("--warn-mem", type=float, default=85.0)
    p.add_argument("--crit-mem", type=float, default=95.0)
    p.add_argument("--warn-nand", type=float, default=80.0)
    p.add_argument("--crit-nand", type=float, default=92.0)
    p.add_argument("--insecure", action="store_true",
                   help="do not verify the TLS certificate (self-signed camera cert)")
    return p.parse_args()


def fetch(args):
    scheme = "http" if args.no_tls else "https"
    port = args.port or (80 if args.no_tls else 443)
    url = "%s://%s:%d%s" % (scheme, args.host, port, args.path)
    ctx = ssl.create_default_context()
    if args.insecure or scheme == "http":
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    req = urllib.request.Request(url, headers={"User-Agent": "check_anjoy_nagios/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=args.timeout, context=ctx) as r:
            body = r.read().decode("utf-8", "replace")
            ctype = r.headers.get("Content-Type", "")
    except urllib.error.HTTPError as e:
        return None, "HTTP %s from %s" % (e.code, url), None
    except Exception as e:  # noqa: BLE001 - report any transport failure as UNKNOWN
        return None, "connection to %s failed: %s" % (url, e), None

    if not body.strip():
        # This is the trap: 200 + empty body. The generator is not producing.
        return None, ("empty body from %s (HTTP 200 -- the vendor server "
                     "returns 200 for missing .txt, so this means the "
                     "generator is dead, NOT that the URL is wrong)" % url), None
    if "json" not in ctype and "text/plain" not in ctype:
        return None, "unexpected Content-Type %r from %s" % (ctype, url), None
    try:
        data = json.loads(body)
    except ValueError as e:
        return None, "payload is not valid JSON (%s) from %s" % (e, url), None
    return data, None, url


def load_state(path):
    try:
        with open(path, "r") as f:
            return json.load(f)
    except Exception:  # noqa: BLE001
        return {}


def save_state(path, state):
    """Atomic write so concurrent checks cannot corrupt the state file."""
    d = os.path.dirname(os.path.abspath(path)) or "."
    try:
        fd, tmp = tempfile.mkstemp(dir=d, prefix=".anjoy.", suffix=".tmp")
        with os.fdopen(fd, "w") as f:
            json.dump(state, f)
        os.replace(tmp, path)
    except Exception:  # noqa: BLE001 - state loss degrades, never crashes the check
        try:
            os.unlink(tmp)
        except Exception:  # noqa: BLE001
            pass


def num(data, key):
    v = data.get(key)
    if v is None or v == "" or v == "n/a":
        return None
    try:
        return float(v)
    except (TypeError, ValueError):
        return None


def threshold(value, warn, crit):
    """Return worst status triggered by value against warn/crit (higher=worse)."""
    if value is None:
        return None
    if crit is not None and value >= crit:
        return CRITICAL
    if warn is not None and value >= warn:
        return WARNING
    return OK


def main():
    args = parse_args()
    state_path = args.state_file or "/tmp/check_anjoy_%s.json" % args.host
    now = time.time()

    data, err, url = fetch(args)
    if data is None:
        # Transport/parse failure is CRITICAL: we cannot claim the device is fine.
        print("CRITICAL - %s" % err)
        return CRITICAL

    msgs = []
    perf = []
    worst = OK

    def bump(s):
        nonlocal worst
        if s is not None and s > worst:
            worst = s

    # --- liveness via heartbeat ------------------------------------------
    prev = load_state(state_path)
    hb = num(data, "heartbeat")
    boot = data.get("boot_id")
    prev_boot = prev.get("boot_id")
    prev_hb = prev.get("heartbeat")
    prev_at = prev.get("at")

    rebooted = bool(prev_boot and boot and prev_boot != boot)
    if rebooted:
        msgs.append("rebooted (boot_id changed)")

    if hb is None:
        msgs.append("no heartbeat in payload")
        bump(CRITICAL)
    elif prev_hb is None:
        msgs.append("first check, heartbeat=%d" % hb)
    elif hb > prev_hb:
        msgs.append("heartbeat %d->%d" % (prev_hb, hb))
    else:
        # heartbeat did not advance
        gap = (now - prev_at) if prev_at else None
        if gap is not None and gap >= args.stale:
            msgs.append("STALE: heartbeat stuck at %d for %.0fs (>%.0fs) "
                       "-- on-device generator is dead" % (hb, gap, args.stale))
            bump(CRITICAL)
        else:
            msgs.append("heartbeat unchanged at %d" % hb)

    # --- thresholds ------------------------------------------------------
    checks = [
        ("temperature_c", "temperature", args.warn_temp, args.crit_temp, "C"),
        ("cpu_used_pct", "cpu", args.warn_cpu, args.crit_cpu, "%"),
        ("mem_used_pct", "memory", args.warn_mem, args.crit_mem, "%"),
        ("nand_used_pct", "nand", args.warn_nand, args.crit_nand, "%"),
    ]
    for key, label, warn, crit, unit in checks:
        v = num(data, key)
        s = threshold(v, warn, crit)
        if v is None:
            msgs.append("%s unavailable" % label)
            continue
        perf.append("%s=%d;%s;%s;0;100" % (
            label, int(v),
            "" if warn is None else int(warn),
            "" if crit is None else int(crit)))
        if s in (WARNING, CRITICAL):
            msgs.append("%s %d%s >= %s%s" % (label, int(v), unit,
                                            int(crit if s == CRITICAL else warn), unit))
        bump(s)

    # --- required services ----------------------------------------------
    for key, label in (("web_server_running", "web_server"),
                      ("watchdog_running", "watchdog")):
        v = num(data, key)
        if v is None:
            msgs.append("%s state unknown" % label)
            bump(UNKNOWN)
        elif v < 1:
            msgs.append("%s NOT running" % label)
            bump(CRITICAL)

    # extra perfdata that is useful for graphing but not thresholded
    for key, label in (("uptime_seconds", "uptime"),
                      ("heartbeat", "heartbeat"),
                      ("mem_avail_kb", "mem_avail_kb"),
                      ("process_count", "processes")):
        v = num(data, key)
        if v is not None:
            perf.append("%s=%d" % (label, int(v)))

    save_state(state_path, {
        "heartbeat": hb,
        "boot_id": boot,
        "at": now,
        "status": STATUS_NAME[worst],
    })

    status = STATUS_NAME[worst]
    summary = ", ".join(m for m in msgs if m)
    line = "%s - %s" % (status, summary)
    if perf:
        line += " | " + " ".join(perf)
    print(line)
    return worst


if __name__ == "__main__":
    sys.exit(main())
