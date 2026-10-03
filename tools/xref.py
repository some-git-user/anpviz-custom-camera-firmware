#!/usr/bin/env python3
"""Find ARM PC-relative (ADR/ADD/LDR literal) references to a target address,
then disassemble the containing region."""
import sys, struct
from capstone import *

PATH = "/home/user/development/firmware/work/build/rootfs/opt/ch/mainctrl"
data = open(PATH, "rb").read()

# R E segment: file 0x000000 -> vaddr 0x00010000, size 0x80060
BASE_V = 0x00010000
BASE_O = 0x000000
SZ = 0x80060

def find_refs(target):
    """Scan .text for instructions that materialize `target` via PC-relative ops."""
    hits = []
    md = Cs(CS_ARCH_ARM, CS_MODE_ARM)
    md.detail = True
    code = data[BASE_O:BASE_O+SZ]
    # decode linearly; for each insn compute pc = addr + 8
    for ins in md.disasm(code, BASE_V):
        pc = ins.address + 8
        # check operands for a literal that equals target
        for op in ins.operands:
            if op.type == 3:  # ARM_OP_IMM
                if op.imm == target:
                    hits.append((ins.address, ins.mnemonic, ins.op_str))
            elif op.type == 2:  # mem
                base = op.mem.base
                disp = op.mem.disp
                if base == 0 and disp == target - pc:
                    hits.append((ins.address, ins.mnemonic, ins.op_str + "  [PC-lit -> target]"))
                elif base == 15:
                    eff = pc + disp
                    if eff == target:
                        hits.append((ins.address, ins.mnemonic, ins.op_str + "  [-> target]"))
        # also: add rd, pc, #imm  where pc+imm == target
        if ins.mnemonic in ("adr", "add") and target - pc >= 0:
            s = ins.op_str
            if "#0x%x" % (target - pc) in s or str(target - pc) == s.split(",")[-1].strip():
                hits.append((ins.address, ins.mnemonic, s + "  [PC-rel -> target]"))
    return hits

def dis(vaddr, size=0x180, mode=CS_MODE_ARM, label=""):
    off = vaddr - BASE_V + BASE_O
    md = Cs(CS_ARCH_ARM, mode)
    md.detail = True
    print("=== %s @ %#x ===" % (label, vaddr))
    for ins in md.disasm(data[off:off+size], vaddr):
        print("0x%06x:\t%s\t%s" % (ins.address, ins.mnemonic, ins.op_str))

if __name__ == "__main__":
    tgt = int(sys.argv[1], 0)
    print("target %#x" % tgt)
    for mode, mname in ((CS_MODE_ARM, "ARM"), (CS_MODE_THUMB, "THUMB")):
        md = Cs(CS_ARCH_ARM, mode)
        n = sum(1 for _ in md.disasm(data[BASE_O:BASE_O+0x1000], BASE_V))
        print(f"  {mname} decode sample count: {n}")
    hits = find_refs(tgt)
    print("ARM hits:", len(hits))
    for h in hits[:20]:
        print("  ", hex(h[0]), h[1], h[2])
