import struct, zlib, hashlib, sys

fn = sys.argv[1]
d = open(fn, "rb").read()
print("file:", fn, "size", hex(len(d)))
print("magic", d[:8])
total = struct.unpack_from("<I", d, 0x0c)[0]
flags = struct.unpack_from("<I", d, 0x10)[0]
kern_off = struct.unpack_from("<I", d, 0x14)[0]
kern_end = struct.unpack_from("<I", d, 0x18)[0]
rootfs_off = struct.unpack_from("<I", d, 0x120)[0]
rootfs_size = struct.unpack_from("<I", d, 0x124)[0]
print("total", hex(total), "filesize", hex(len(d)), "MATCH" if total == len(d) else "MISMATCH")
print("flags", flags, "kern", hex(kern_off), hex(kern_end))
print("rootfs_off", hex(rootfs_off), "rootfs_size", hex(rootfs_size),
      "(%d bytes)" % rootfs_size)
print("rootfs_off+size", hex(rootfs_off + rootfs_size),
      "<= filesize?", rootfs_off + rootfs_size <= len(d))
print("rootfs ceiling 9355264 ok?", rootfs_size <= 9355264)
hdr = bytearray(d[:0x614]); hdr[8:12] = b"\0" * 4
calc = zlib.crc32(bytes(hdr)) & 0xffffffff
stored = struct.unpack_from("<I", d, 8)[0]
print("hdr_crc calc", hex(calc), "stored", hex(stored), "MATCH" if calc == stored else "MISMATCH")
print("rootfs magic", d[rootfs_off:rootfs_off + 4])
print("rootfs sha256", hashlib.sha256(d[rootfs_off:rootfs_off + rootfs_size]).hexdigest()[:16])
print("devname", d[0x128:0x228].split(b"\0")[0].decode(errors="replace"))
