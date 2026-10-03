#!/usr/bin/env python3
"""Inspect the ANJOY888 dashcam update container (MC500L / AF-RTMP-H5)."""
import struct
import sys

PATH = sys.argv[1] if len(sys.argv) > 1 else (
    "firmware_MC500L_V0_AF-RTMP-H5_V3.2.1.2_Y_EN_YM500L_V0_202301101555.bin")
d = open(PATH, "rb").read()
print("file size: %d (%#x)" % (len(d), len(d)))


def hexdump(off, n, label=""):
    print("--- %s @ %#x" % (label, off))
    for i in range(0, n, 16):
        chunk = d[off + i:off + i + 16]
        txt = "".join(chr(c) if 32 <= c < 127 else "." for c in chunk)
        print("%08x  %-48s %s" % (off + i, chunk.hex(" "), txt))


hexdump(0, 0x40, "container header")
hexdump(0x120, 0x60, "device-name / sizes record")

# --- uImage (legacy) at 0x614 -------------------------------------------
uo = 0x614
magic, mtime, size, load, ep, dcrc, comp, os_, arch = struct.unpack(">9I", d[uo:uo + 36])
name = d[uo + 36:uo + 100].rstrip(b"\0")
print("\n[uImage @ %#x] magic=%#x img_size=%#x load=%#x ep=%#x comp=%d name=%r"
      % (uo, magic, size, load, ep, comp, name))
print("  image data: %#x .. %#x" % (uo + 64, uo + 64 + size))

# --- squashfs -----------------------------------------------------------
SQ = b"hsqs"
off = 0
while True:
    off = d.find(SQ, off)
    if off < 0:
        break
    (magic, inodes, mkfs_time, block_size, fragments, block_log, flags, no_ids,
     s_major, s_minor, root_inode, bytes_used, id_table, xattr_ids,
     xattr_table) = struct.unpack("<IIIIIHHHHHqqqqq", d[off:off + 70])
    CM = {1: "jffs2", 2: "gzip", 4: "lzma", 8: "lzo", 16: "xz", 32: "zstd", 0: "none"}
    print("\n[squashfs @ %#x] v%d.%d  bytes_used=%#x  end=%#x  block=%d comp=%s(%d) inodes=%d"
          % (off, s_major, s_minor, bytes_used, off + bytes_used,
             block_size, CM.get(flags >> 8, "?"), flags >> 8, inodes))
    off += 1

# --- gzip ---------------------------------------------------------------
off = 0
while True:
    off = d.find(b"\x1f\x8b\x08", off)
    if off < 0:
        break
    print("\n[gzip @ %#x]" % off)
    hexdump(off, 32, "gzip header")
    off += 1
