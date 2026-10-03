# MC500L Firmware — Web UI repack workflow

Tooling to modify the web UI of the **ANJOY888** dashcam firmware
(`firmware_MC500L_V0_AF-RTMP-H5_V3.2.1.2_...bin`, MStar I3 / Linux)
and repack it into a flashable `.bin`.

## Quick start

```bash
./extract.sh                 # unpack into ./work/
# edit the web UI in  work/rootfs/var/www/
./pack.sh                    # build ./firmware_custom.bin
```

Optional arguments:

```bash
./extract.sh <input.bin> <workdir>     # defaults: original .bin, ./work
./pack.sh   <workdir> <output.bin>     # defaults: ./work, ./firmware_custom.bin
```

The web UI lives in **`work/rootfs/var/www/`** (`index.html`, `js/`, `css/`,
`html/*Config.html`, `lib/`, images). Edit those files and repack.

## Requirements

- `squashfs-tools` (`unsquashfs`, `mksquashfs`) — squashfs 4.0, XZ, 128 KiB blocks
- Python 3

## How the container works

Little-endian header, then kernel, then the rootfs:

| Offset | Field | Value |
|--------|-------|-------|
| `0x000` | magic | `ANJOY888` |
| `0x008` | **header CRC32** | CRC32 of `[0x000:0x614)` with this field zeroed |
| `0x00C` | total size | total `.bin` size |
| `0x010` | flags | `0x3` (bit0 = rootfs present, bit1 = 2nd image) |
| `0x014` / `0x018` | kernel off / end | `0x614` / `0x1d0c14` |
| `0x020` | platform | `MSTAR_I3_LINUX` |
| `0x120` | rootfs offset | `0x1d1228` |
| `0x124` | rootfs size | squashfs size, padded to `0x1000` |
| `0x128` | device name | `MC500L_V0_AF-RTMP-H5_V3.2.1.2_...` |
| `0x614` | kernel | uImage — **MStar MVX2 encrypted**, copied verbatim |
| `0x1d1228` | **rootfs** | **SquashFS 4.0, XZ, block 131072** (web UI here) |

The device's `CheckFirmwareBuf` (in `opt/ch/libtools.so`) verifies the
**0x614-byte header CRC32** and the size fields. `tools/anjoy.py` recomputes
this on repack, so the container passes validation. The encrypted kernel is
never touched — only the plain squashfs rootfs is rebuilt.

## What `pack.sh` does

1. Rebuilds the squashfs with the original parameters
   (`-comp xz -b 131072 -no-xattrs -all-root`).
2. Pads it to `0x1000`.
3. Copies the original header + kernel + gap verbatim.
4. Updates `rootfs_size` and `total_size`.
5. Recomputes the header CRC32.

`SOURCE_DATE_EPOCH` is pinned to the original build time
(`1673337341` = 2023-01-10 08:55:41 UTC) so the squashfs timestamp matches
and **our own rebuilds are byte-for-byte reproducible**.

## Do the old and new `.bin` share the same hash?

**No — and they are not expected to.** Verified with the workflow above:

| File | SHA-256 |
|------|---------|
| original | `0164e2706ef761cd...7d24e7a0` |
| repacked (no edits) | `ebae713477666644...51cbbad0` |

The two files are **functionally identical** — same header, same encrypted
kernel, same extracted rootfs content (all files and symlinks match). The
hash differs only because:

- **XZ compression is not bit-reproducible across versions.** The vendor's
  `xz`/`mksquashfs` produced different compressed bytes than ours for the
  same input. This changes ~46% of the file's bytes even with zero edits.
- The squashfs timestamp is now pinned, so that is no longer a source of
  difference between our own builds.

**What "the workflow works fine" actually means:**

- Header CRC32 recomputes to the original value (`0xeea0b26d`). ✅
- Header + kernel regions are byte-identical to the original. ✅
- Re-extracting the repacked `.bin` yields a rootfs identical to the source. ✅
- Two consecutive `./pack.sh` runs produce the **same** SHA-256
  (reproducible). ✅

So use the hash to confirm **reproducibility of your own builds**, not to
match the vendor's original. The device checks the header CRC and sizes, not
a whole-file SHA-256.

## Files

- `extract.sh` — unpack the firmware
- `pack.sh` — repack the firmware
- `tools/anjoy.py` — the unpack/repack engine (layout, CRC, squashfs params)
- `tools/inspect.py` — dump/inspect the container layout
- `tools/dis.py` — capstone helper used to reverse `libtools.so`

## Caveats

- Keep the device-name string at `0x128` matching your model or the updater
  may reject the image.
- If you bump the version, update it in the header name and in the UI /
  `version.txt` so the device does not treat it as same-or-older.
- Flash at your own risk; test on a device you can recover.
