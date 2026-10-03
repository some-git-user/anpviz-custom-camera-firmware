#!/usr/bin/env python3
"""
ANJOY888 dashcam firmware unpack/repack tool
==========================================
Target: firmware_MC500L_V0_AF-RTMP-H5_V3.2.1.2_...bin  (MStar I3 / Linux)

Container layout (all little-endian):
  0x000  magic          "ANJOY888"            (8 bytes)
  0x008  header_crc32   CRC32 of [0x000:0x614) with THIS field zeroed
  0x00C  total_size     total .bin size
  0x010  flags          bit0 = rootfs present, bit1 = 2nd component present
  0x014  kern_off       kernel (uImage, MStar-encrypted) start  = 0x614
  0x018  kern_end       kernel end / gap start
  0x020  platform       "MSTAR_I3_LINUX"
  0x120  rootfs_off     squashfs rootfs offset
  0x124  rootfs_size    squashfs size, rounded up to 0x1000
  0x128  device_name    "MC500L_V0_AF-RTMP-H5_V3.2.1.2_Y_EN_YM500L_V0"
  0x230  comp2_size     second component size (0 here)
  0x614  kernel         uImage (MVX2 encrypted) -- kept byte-for-byte
  ....   zero gap       padding up to rootfs_off
  rootfs_off  squashfs rootfs (xz, block 131072) -- THE WEB UI LIVES HERE
  ....   zero padding   up to total_size

The web UI is <rootfs>/var/www (index.html, js/, css/, html/, ...).
Only the rootfs is modified; the encrypted kernel is copied verbatim.
"""
import os
import struct
import subprocess
import sys
import zlib

HDR_MAGIC = b"ANJOY888"
HDR_LEN = 0x614
ROOTFS_ALIGN = 0x1000
# Original squashfs build timestamp -> reproducible rebuilds.
SOURCE_DATE_EPOCH = 1673337341  # 2023-01-10 08:55:41 UTC

# header field offsets
O_CRC = 0x08
O_TOTAL = 0x0C
O_FLAGS = 0x10
O_KERN_OFF = 0x14
O_KERN_END = 0x18
O_ROOTFS_OFF = 0x120
O_ROOTFS_SIZE = 0x124
O_DEVNAME = 0x128
O_ROOTFS_CRC = 0x228  # CRC32 over the PADDED rootfs region (verified against
                       # v343 + v345 stock: stored == crc32(rootfs[0:size]))
O_KERN_CRC = 0x1C      # kernel checksum (kernel is copied verbatim -> unchanged)
O_COMP2_SIZE = 0x230


def rd(path):
    with open(path, "rb") as f:
        return f.read()


def u32(buf, off):
    return struct.unpack_from("<I", buf, off)[0]


def put_u32(buf, off, val):
    buf[off:off + 4] = struct.pack("<I", val & 0xFFFFFFFF)


def header_crc(header_bytes):
    """CRC32 over the 0x614-byte header with the CRC field itself zeroed."""
    h = bytearray(header_bytes[:HDR_LEN])
    h[O_CRC:O_CRC + 4] = b"\x00\x00\x00\x00"
    return zlib.crc32(bytes(h)) & 0xFFFFFFFF


# --------------------------------------------------------------------------
def unpack(bin_path, out_dir):
    data = rd(bin_path)
    assert data[:8] == HDR_MAGIC, "not an ANJOY888 container"
    rootfs_off = u32(data, O_ROOTFS_OFF)
    rootfs_size = u32(data, O_ROOTFS_SIZE)

    os.makedirs(out_dir, exist_ok=True)
    # whole header (0 .. rootfs_off) is kept verbatim for repack
    with open(os.path.join(out_dir, "header.bin"), "wb") as f:
        f.write(data[:rootfs_off])
    # the squashfs image itself (use bytes_used, not the padded size)
    sq = data[rootfs_off:rootfs_off + rootfs_size]
    # trim trailing zero padding to the real squashfs length
    sq_stripped = sq.rstrip(b"\x00")
    # find real end via superblock bytes_used
    if sq[:4] == b"hsqs":
        bytes_used = struct.unpack_from("<q", sq, 40)[0]
        sq = sq[:bytes_used]
    with open(os.path.join(out_dir, "rootfs.squashfs"), "wb") as f:
        f.write(sq)
    # trailing bytes after rootfs (if any)
    tail = data[rootfs_off + rootfs_size:]
    with open(os.path.join(out_dir, "tail.bin"), "wb") as f:
        f.write(tail)

    print("header.bin   : %#x bytes (0..%#x)" % (rootfs_off, rootfs_off))
    print("rootfs.sqfs  : %#x bytes @ %#x" % (len(sq), rootfs_off))
    print("tail.bin     : %#x bytes" % len(tail))
    print("extracting web rootfs -> %s/rootfs" % out_dir)
    subprocess.run(["unsquashfs", "-force", "-d",
                   os.path.join(out_dir, "rootfs"),
                   os.path.join(out_dir, "rootfs.squashfs")], check=True)


# --------------------------------------------------------------------------
def repack(rootfs_dir, header_bin, out_bin, rootfs_off=None):
    data_hdr = bytearray(rd(header_bin))
    if rootfs_off is None:
        rootfs_off = len(data_hdr)

    # rebuild squashfs with the SAME params as the original.
    # Pin SOURCE_DATE_EPOCH so our own rebuilds are reproducible
    # (matches the original squashfs build timestamp when unchanged).
    env = dict(os.environ)
    env.setdefault("SOURCE_DATE_EPOCH", str(SOURCE_DATE_EPOCH))
    sq_path = os.path.join(os.path.dirname(rootfs_dir.rstrip("/")),
                          "rootfs_new.squashfs")

    # Auto-detect the original squashfs block size so we match the vendor exactly.
    # (MC500L uses 131072, MCF46D uses 262144 -- hardcoding breaks the match.)
    block_size = 131072
    orig_sq = os.path.join(os.path.dirname(os.path.abspath(header_bin)),
                          "rootfs.squashfs")
    if os.path.exists(orig_sq):
        try:
            with open(orig_sq, "rb") as _f:
                _sb = _f.read(32)
            _bs = struct.unpack("<I", _sb[12:16])[0]
            if _bs >= 4096 and (_bs & (_bs - 1)) == 0:
                block_size = _bs
        except Exception:
            pass
    print("squashfs block size: %d" % block_size)

    subprocess.run([
        "mksquashfs", rootfs_dir, sq_path,
        "-comp", "xz", "-b", str(block_size),
        "-noappend", "-no-xattrs", "-all-root",
    ], check=True, env=env)
    sq = rd(sq_path)

    # pad rootfs to 0x1000
    padded = ((len(sq) + ROOTFS_ALIGN - 1) // ROOTFS_ALIGN) * ROOTFS_ALIGN
    sq = sq + b"\x00" * (padded - len(sq))

    # original kernel+gap = header .. rootfs_off  (kept verbatim)
    pre = bytes(data_hdr)  # 0 .. rootfs_off (header + kernel + gap)
    total = rootfs_off + len(sq)

    out = bytearray(pre) + bytearray(sq)
    put_u32(out, O_ROOTFS_SIZE, len(sq))
    put_u32(out, O_TOTAL, total)

    # CRITICAL: the updater verifies a per-component CRC32 stored in the header.
    # Without this, any modified rootfs is rejected (silently -- the version
    # page just keeps showing the old build). Verified against v343/v345 stock:
    # header@0x228 == crc32(rootfs_bytes_including_0x1000_padding).
    rootfs_crc = zlib.crc32(bytes(sq)) & 0xFFFFFFFF
    put_u32(out, O_ROOTFS_CRC, rootfs_crc)

    # recompute CRC over the (updated) header with CRC field zeroed
    crc = header_crc(out)
    put_u32(out, O_CRC, crc)

    with open(out_bin, "wb") as f:
        f.write(out)
    print("wrote %s  total=%#x  rootfs_size=%#x  hdr_crc=%#010x  rootfs_crc=%#010x"
          % (out_bin, total, len(sq), crc, rootfs_crc))


# --------------------------------------------------------------------------
if __name__ == "__main__":
    cmd = sys.argv[1] if len(sys.argv) > 1 else "help"
    if cmd == "unpack":
        unpack(sys.argv[2], sys.argv[3])
    elif cmd == "repack":
        # repack <rootfs_dir> <header.bin> <out.bin> [rootfs_off]
        off = int(sys.argv[5], 16) if len(sys.argv) > 5 else None
        repack(sys.argv[2], sys.argv[3], sys.argv[4], off)
    else:
        print(__doc__)
