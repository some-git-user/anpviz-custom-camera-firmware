#!/usr/bin/env python3
"""Generic PC-relative xref finder for ARM/Thumb ELF binaries.

Usage: xref2.py <binary> <hex-addr-or-string> [window_bytes]

Given a target virtual address (or a literal string, which is looked up in the
ELF to derive its vaddr), scan .text for ARM/Thumb instructions that
materialise that address via ADR/ADD-with-PC or a PC-relative literal load.
Prints each hit with a disassembly window around it.
"""
import subprocess
import sys

from capstone import *
from capstone.arm_const import ARM_INS_INVALID, ARM_OP_IMM, ARM_OP_MEM

PATH = sys.argv[1]
TARGET = sys.argv[2]
WINDOW = int(sys.argv[3], 0) if len(sys.argv) > 3 else 0x120

data = open(PATH, "rb").read()

# --- readelf: section table -------------------------------------------------
sec = subprocess.run(["readelf", "-SW", PATH], capture_output=True, text=True).stdout
text = rodata = None
for line in sec.splitlines():
    if ".text " in line and "PROGBITS" in line:
        p = line.split()
        i = p.index(".text")
        # columns: [Nr] Name Type Addr Off Size ES Flg ...
        text = (int(p[i + 2], 16), int(p[i + 3], 16), int(p[i + 4], 16))
    elif ".rodata" in line and "PROGBITS" in line:
        p = line.split()
        i = p.index(".rodata")
        rodata = (int(p[i + 2], 16), int(p[i + 3], 16), int(p[i + 4], 16))

# --- resolve a string target to a vaddr -------------------------------------
if not TARGET.startswith("0x"):
    needle = TARGET.encode()
    off = data.find(needle)
    while off != -1:
        if rodata and rodata[1] <= off < rodata[1] + rodata[2]:
            TARGET = hex(off - rodata[1] + rodata[0])
            print(f"# string {TARGET!r} found at file 0x{off:x} -> vaddr {TARGET}")
            break
        off = data.find(needle, off + 1)
    else:
        print("# string not found in .rodata")
        sys.exit(1)

tgt = int(TARGET, 16)
print(f"# target vaddr {tgt:#x}  (.text {text[0]:#x}+{text[2]:#x})")

md = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
md.detail = True
# skipdata is ESSENTIAL: without it capstone's linear sweep stops at the first
# halfword it cannot decode. In this binary that means ~1341 instructions out of
# ~927k, so the scan silently covered 0.1% of .text and reported "no refs".
md.skipdata = True
code = data[text[1]:text[1] + text[2]]
base = text[0]

hits = []
for ins in md.disasm(code, base):
    if ins.id == ARM_INS_INVALID:
        continue
    # ARM/Thumb: PC == insn_address + 8 (both modes on ARMv7 for these ops)
    pc = ins.address + 8
    for op in ins.operands:
        if op.type == ARM_OP_IMM and op.imm == tgt:
            hits.append((ins.address, ins.mnemonic, ins.op_str, "imm"))
        elif op.type == ARM_OP_MEM and op.mem.base == 15:
            eff = pc + op.mem.disp
            if eff == tgt:
                hits.append((ins.address, ins.mnemonic, ins.op_str, "pc-lit"))
    if ins.mnemonic in ("adr", "add") and ins.op_str.startswith("r"):
        # add rd, pc, #imm
        if ", pc" in ins.op_str.replace("r15", "pc"):
            try:
                imm = int(ins.op_str.split("#")[-1], 0)
                if pc + imm == tgt:
                    hits.append((ins.address, ins.mnemonic, ins.op_str, "adr/add"))
            except ValueError:
                pass

if not hits:
    print("# no PC-relative references found")
    sys.exit(0)

for addr, mnem, ops, kind in hits:
    print(f"\n=== ref @ {addr:#x} ({kind}): {mnem} {ops}")
    lo = addr - WINDOW // 2
    if lo < base:
        lo = base
    buf = data[text[1] + (lo - base): text[1] + (addr - base) + 16]
    for i in md.disasm(buf, lo):
        mark = ">>" if i.address == addr else "  "
        ann = ""
        if i.mnemonic in ("ldr", "ldrl") and "[pc" in i.op_str:
            try:
                disp = int(i.op_str.split("#0x")[-1].rstrip("]"), 16)
                a = i.address + 8 + disp
                if rodata[0] <= a < rodata[0] + rodata[2]:
                    fo = a - rodata[0] + rodata[1]
                    s = data[fo:data.index(b"\0", fo)].decode("latin1")
                    if s:
                        ann = f'   ; "{s[:70]}"'
            except Exception:
                pass
        print(f"{mark} {i.address:#08x}  {i.mnemonic:<8} {i.op_str}{ann}")
