#!/usr/bin/env python3
"""Disassemble an ARM/Thumb function out of libtools.so using capstone."""
import sys
from capstone import *

LIB = "/home/user/development/firmware/work/rootfs/opt/ch/libtools.so"
data = open(LIB, "rb").read()

# Map vaddr -> file offset via program headers
import struct
phoff = struct.unpack_from("<I", data, 0x1C)[0]
phentsize = struct.unpack_from("<H", data, 0x2A)[0]
phnum = struct.unpack_from("<H", data, 0x2C)[0]
segs = []
for i in range(phnum):
    o = phoff + i * phentsize
    p_type, p_off, p_vaddr, _, p_filesz, p_memsz = struct.unpack_from("<IIIIII", data, o)
    if p_type == 1:
        segs.append((p_vaddr, p_off, p_filesz))


def v2o(v):
    for va, off, sz in segs:
        if va <= v < va + sz:
            return off + (v - va)
    raise ValueError("no segment for %#x" % v)


def disasm(vaddr, size=None, thumb=True, label=""):
    md = Cs(CS_ARCH_ARM, CS_MODE_THUMB if thumb else CS_MODE_ARM)
    md.detail = True
    off = v2o(vaddr)
    if size is None:
        size = 0x300
    code = data[off:off + size]
    print("=== %s @ %#x (thumb=%s) ===" % (label, vaddr, thumb))
    for ins in md.disasm(code, vaddr):
        print("0x%06x:\t%s\t%s" % (ins.address, ins.mnemonic, ins.op_str))


if __name__ == "__main__":
    va = int(sys.argv[1], 16)
    thumb = (va & 1) == 1
    va &= ~1  # Thumb symbols carry LSB=1; code lives at the even address
    sz = int(sys.argv[2], 16) if len(sys.argv) > 2 else 0x200
    lbl = sys.argv[3] if len(sys.argv) > 3 else ""
    disasm(va, sz, thumb=thumb, label=lbl)
