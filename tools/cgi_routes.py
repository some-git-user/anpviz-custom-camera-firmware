#!/usr/bin/env python3
"""Dump the /cgi-bin route table from libcgibin_curl.so.

The table is an array of {char *route_name, handler} pairs living in .data,
referenced by R_ARM_ABS32 relocations. The name pointer resolves to a .rodata
string; the handler resolves to a cgi_* function.
"""
import re
import struct
import subprocess
import sys

LIB = sys.argv[1] if len(sys.argv) > 1 else \
    "builds/YMF46D/rootfs/opt/ch/libcgibin_curl.so"

d = open(LIB, "rb").read()

secout = subprocess.run(["readelf", "-SW", LIB], capture_output=True,
                       text=True).stdout
secs = []
for line in secout.splitlines():
    m = re.match(
        r"\s*\[\s*\d+\]\s+(\S+)\s+(\S+)\s+([0-9a-f]+)\s+([0-9a-f]+)\s+([0-9a-f]+)",
        line)
    if m:
        secs.append((m.group(1), int(m.group(3), 16), int(m.group(4), 16),
                     int(m.group(5), 16)))


def v2o(x):
    for n, a, o, s in secs:
        if a and a <= x < a + s:
            return o + (x - a)
    return None


def cstr(o, maxlen=80):
    if o is None or o >= len(d):
        return None
    try:
        e = d.index(b"\0", o)
    except ValueError:
        return None
    if e - o < 1 or e - o > maxlen:
        return None
    s = d[o:e].decode("utf8", "replace")
    return s if all(32 <= ord(c) < 127 for c in s) else None


rel = {}
for line in subprocess.run(["readelf", "-rW", LIB], capture_output=True,
                          text=True).stdout.splitlines():
    m = re.match(r"([0-9a-f]+)\s+\S+\s+(R_ARM_ABS32)\s+([0-9a-f]+)\s+(\S+)", line)
    if m:
        rel[int(m.group(1), 16)] = (int(m.group(3), 16), m.group(4))

handler_offs = sorted(o for o, (v, n) in rel.items() if re.search(r"cgi", n))

runs, cur = [], [handler_offs[0]]
for o in handler_offs[1:]:
    if o - cur[-1] <= 16:
        cur.append(o)
    else:
        runs.append(cur)
        cur = [o]
runs.append(cur)
runs.sort(key=len, reverse=True)

# The table is {name_ptr, handler_ptr} pairs. Only the HANDLER half carries a
# relocation (it points at an exported function); the name pointer is a plain
# .rodata address stored directly in .data, so resolve it with v2o, not rel.
# Scan the whole writable region for 8-byte-aligned pairs whose first word is a
# "/cgi-bin/..." string -- more reliable than anchoring on the handler runs.
data = next((s for s in secs if s[0] == ".data"), None)
if data is None:
    print("no .data section")
    sys.exit(1)
_, daddr, doff, dsz = data

rows = []
for off in range(0, dsz - 8, 4):
    w = struct.unpack_from("<I", d, doff + off)[0]
    s = cstr(v2o(w))
    if not (s and s.startswith("/cgi-bin/")):
        continue
    hw = struct.unpack_from("<I", d, doff + off + 4)[0]
    hd = rel.get(daddr + off + 4, (hw, f"0x{hw:x}"))[1]
    rows.append((daddr + off, s, hd))

print(f"entries: {len(rows)}\n")
print(f"{'offset':<10} {'route':<48} handler")
print("-" * 96)
for a, nm, hd in rows:
    print(f"0x{a:x}    {nm:<48} {hd}")
