# ANJOY888 camera firmware — multi-camera repack workflow

Tooling to modify the web UI / rootfs of **ANJOY888** container dashcam
firmware (SStar / MStar Linux) and repack it into a flashable `.bin`, with
each supported camera kept clearly separated in the repo.

## Supported cameras

| Slug | Device name | Stock firmware(s) |
|------|-------------|-------------------|
| `YM500L` | `MC500L_V0_AF-RTMP-H5_V3.2.1.2_Y_EN_YM500L_V0` | 3.2.1.2 (2023) |
| `YMF46D` | `MCF46D_V4_AF-RTMP-A-H5_V3.4.5.2_Y_EN_YMF46D_V4_...` | 3.4.3.2, 3.4.5.2 (2025) |

The slug is derived automatically from the image header (`device_name` @ `0x128`),
so a working tree is always named after the camera the firmware actually targets —
never guessed from the filename.

## Repository layout

```
stock/<CAM>/       pristine vendor .bin images        (TRACKED — already xz-compressed)
builds/<CAM>/      editable working tree            (TRACKED — this is where edits live)
    rootfs/            unpacked root filesystem
    header.bin         header + encrypted kernel, kept verbatim for repack
    build.info         per-camera params (slug, version, rootfs_off, squashfs block size)
    CHANGELOG.txt      what we changed vs stock, newest first (kept up to date by hand)
out/               packed flashable images          (IGNORED — reproducible via pack.sh)
tools/             unpack/repack + helper scripts   (TRACKED)
extract.sh         unpack any .bin -> builds/<slug>/
pack.sh            pack builds/<slug>/ -> out/<slug>_<tag>.bin
```

## Quick start

```bash
# Unpack a firmware image; the slug is read from the header automatically.
./extract.sh stock/YMF46D/firmware_YMF46D_V3.4.5.2_stock.bin
#   -> builds/YMF46D/rootfs/   (edit the web UI here: var/www/)

# Build a flashable image. The build tag auto-increments (see "Version scheme").
./pack.sh YMF46D
#   -> out/YMF46D_3.4.5.2-custom1.bin
# Or give the output file an explicit name:
./pack.sh YMF46D mytest
#   -> out/YMF46D_mytest.bin
```

## Version scheme

Custom builds are tagged `<stock version>-custom<N>` — e.g. `V3.4.5.2-custom1`.
The base version is read from `builds/<slug>/build.info`, so the tag always
follows the stock firmware the tree is actually based on. `N` auto-increments on
every `./pack.sh` run from `builds/<slug>/custom_build`.

The tag is stamped into the rootfs at build time:
- `etc/filesys.ver` — keeps the vendor prefix (`_Y_EN-RTMP-H5_L`) and replaces
  only the version token and build date.
- `var/www/CUSTOM_BUILD.txt` — human-readable build identity, served by the web UI.

Pin an exact tag with `CUSTOM_TAG=3.4.5.2-custom7 ./pack.sh YMF46D` (skips the
auto-increment). Earlier development builds used `HTTPS2`..`HTTPS11` labels; that
scheme is retired — see each camera's `CHANGELOG.txt` for the mapping.

`extract.sh` refuses to overwrite an existing `builds/<slug>/rootfs` (your edits
live there). Use `--force` to replace it with a fresh extraction, or `--as SLUG`
to override the auto-detected slug. Compressed inputs (`.xz`, `.gz`, `.zst`) are
decompressed transparently.

`pack.sh` regenerates a fresh self-signed TLS cert and a recovery-telnet password
on every build; that secret material is gitignored and never committed (see
`pack.sh` env overrides: `HTTPS_PASS`, `HTTPS_CN`, `HTTPS_DAYS`, `RECOVERY_PASS`).

The web UI lives in **`builds/<CAM>/rootfs/var/www/`** (`index.html`, `js/`,
`css/`, `html/*Config.html`, `lib/`, images).

## Adding a new camera

1. Drop the vendor `.bin` into `stock/<CAM>/` with a normalised name
   (`firmware_<CAM>_V<version>_stock.bin`).
2. `./extract.sh stock/<CAM>/firmware_<CAM>_V<version>_stock.bin`
3. Create `builds/<CAM>/CHANGELOG.txt` documenting the stock baseline.
4. Edit `builds/<CAM>/rootfs/`, then `./pack.sh <CAM> <name>`.

Keep `CHANGELOG.txt` current: every change made to a build tree after the stock
extract gets an entry (newest first) with what changed, why, and how it was
verified. `git log` has the diffs; the changelog has the reasoning.

## Requirements

- `squashfs-tools` (`unsquashfs`, `mksquashfs`) — squashfs 4.0, XZ
  (block size is auto-detected per camera: YM500L = 128 KiB, YMF46D = 256 KiB)
- Python 3
- `openssl` (for the TLS cert / password hashing in `pack.sh`)

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
