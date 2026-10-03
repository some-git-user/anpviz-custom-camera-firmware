#!/usr/bin/env python3
"""Disassemble a function by symbol name from an ARM ELF, annotating string refs."""
import re
import struct
import subprocess
import sys

from capstone import *

LIB = sys.argv[1]
SYM = sys.argv[2]

d = open(LIB, "rb").read()

out = subprocess.run(["readelf", "-sW", LIB], capture_output=True, text=True).stdout
target = None
for line in out.splitlines():
    if SYM in line and "FUNC" in line:
        parts = line.split()
        v = int(parts[1], 16)
        sz = int(parts[2])
        if v:
            target = (v, sz)
            break
if not target:
    print("symbol not found")
    sys.exit(1)

v, sz = target
out2 = subprocess.run(["readelf", "-SW", LIB], capture_output=True, text=True).stdout
secs = []
for line in out2.splitlines():
    m = re.match(
        r"\s*\[\s*\d+\]\s+(\S+)\s+(\S+)\s+([0-9a-f]+)\s+([0-9a-f]+)\s+([0-9a-f]+)", line)
    if m:
        secs.append((m.group(1), int(m.group(3), 16), int(m.group(4), 16),
                     int(m.group(5), 16)))


def v2o(x):
    for n, a, o, s in secs:
        if a and a <= x < a + s:
            return o + (x - a)
    return None


def cstr(o, maxlen=120):
    if o is None or o >= len(d):
        return None
    try:
        e = d.index(b"\0", o)
    except ValueError:
        return None
    if e - o < 1 or e - o > maxlen:
        return None
    s = d[o:e].decode("utf8", "replace")
    if all(32 <= ord(c) < 127 for c in s):
        return s
    return None


IDENT = set(
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-.:/+%,()[]{}#*")


def cstr_expanded(o, maxlen=200):
    """Resolve a C string at `o`, then walk backwards over identifier chars.

    GCC/Thumb literal pools often point into the MIDDLE of a merged string table
    entry, so the naive read yields a suffix like '_uid_or_username'. Walking
    back to the first non-identifier byte recovers the full symbol/route name.
    """
    s = cstr(o, maxlen)
    if s is None:
        return None
    # walk back
    back = 0
    while back < 80 and o - back - 1 >= 0 and d[o - back - 1] in {
            ord(c)
            for c in IDENT
    }:
        back += 1
    if back == 0:
        return s
    full = cstr(o - back, maxlen)
    return full if full and full.endswith(s) else s


start = v & ~1
thumb = bool(v & 1)
mode = CS_MODE_THUMB if thumb else CS_MODE_ARM
off = v2o(start)
md = Cs(CS_ARCH_ARM, mode)
md.detail = True
code = d[off:off + (sz or 512)]

# symbol lookup for call targets
symmap = {}
for line in out.splitlines():
    p = line.split()
    if len(p) >= 8 and p[3] == "FUNC":
        try:
            sv = int(p[1], 16)
        except ValueError:
            continue
        if sv:
            symmap[sv & ~1] = p[7]

print(f"=== {SYM} @0x{v:x} size={sz} mode={mode} ===")
for ins in md.disasm(code, start):
    line = f"{ins.address:8x}  {ins.bytes.hex():<10} {ins.mnemonic} {ins.op_str}"
    m = re.search(r"\[pc,\s*#(0x[0-9a-f]+|\d+)\]", ins.op_str)
    if m and ins.mnemonic.startswith("ldr"):
        imm = int(m.group(1), 0)
        # Thumb: PC during the ldr == addr + 4, rounded down to 4.
        # ARM:   PC during the ldr == addr + 8.
        base = ((ins.address + 4) & ~3) if thumb else (ins.address + 8)
        pool = base + imm
        word = None
        po = v2o(pool)
        if po is not None and po + 4 <= len(d):
            word = struct.unpack_from("<I", d, po)[0]
        if word is not None:
            pool = base + imm
            a = ins.address
            cands = [
                ("direct", word),
                ("+Align(A+4)", word + ((a + 4) & ~3)),
                ("+Align(A+8)", word + ((a + 8) & ~3)),
                ("+Align(A+12)", word + ((a + 12) & ~3)),
                ("pool+word", pool + word),
            ]
            best = None
            for tag, c in cands:
                st = cstr_expanded(v2o(c), maxlen=200)
                if st and (best is None or len(st) > len(best[1])):
                    best = (tag, st)
            if best:
                line += f"   ; ->({best[0]}) {best[1]!r}"
            else:
                line += f"   ; pool@0x{pool:x}=0x{word:x}"
    cm = re.match(r"(bl|blx|b|b\.w|bl\.w)\s+#?(0x[0-9a-f]+|\d+)", ins.op_str)
    if cm:
        t = int(cm.group(2), 0)
        if t in symmap:
            line += f"   ; {symmap[t]}"
    print(line)
