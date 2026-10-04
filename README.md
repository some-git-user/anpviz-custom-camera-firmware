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

## First-time setup (per clone)

One step:

```bash
./tools/install_hooks.sh      # install the pre-push PII gate
```

## Talking to a camera

Every network tool takes the camera the same way — argument, `CAM_IP`, or it
asks you:

```bash
./tools/ctl3.exp "uname -a" 192.0.2.11   # explicit
./tools/ctl3.exp "uname -a"                    # prompts: camera IP: _
CAM_IP=192.0.2.11 ./tools/ctl3.exp "uname -a"
```

### `ctl3.exp` — run one command over the recovery shell

```bash
./tools/ctl3.exp "cat /proc/mtd" 192.0.2.11
./tools/ctl3.exp "free; df" 192.0.2.11
./tools/ctl3.exp "grep . /tmp/hwinfo.txt" 192.0.2.11
```

Password comes from `RECLOGIN_PASS`, else `tools/.reclogin_pass.<ip>`, else the
shared `tools/.reclogin_pass`. Telnet must be enabled on the device (Network →
Service Ports → Telnet).

### `hwdebug.exp` — full diagnostic battery

```bash
./tools/hwdebug.exp 192.0.2.11
```

Needs the SD-card recovery shell: drop an empty `telnet.enable` on the SD card
and power-cycle.

### `verify_flash.sh` — did my flash actually land?

```bash
./tools/verify_flash.sh 192.0.2.11
```

The vendor web server returns HTTP 200 with a Welcome page for *missing* files,
so the status code alone is worthless — the canary's contents are what decide.
Exits 0 custom, 1 stock, 2 unclear.

### `check_anjoy_nagios.py` — monitoring plugin

Runs from cron/Nagios, so it never prompts. Give it `--host` or `CAM_IP`:

```bash
tools/check_anjoy_nagios.py --host 192.0.2.10 --insecure \
    --user nagios --password '...' \
    --state-file /var/tmp/check_anjoy_cam.json \
    --stale 90 --warn-temp 75 --crit-temp 85
```

### `pack.sh` — the build

Building is entirely offline. The IP here only *names* the recovery-password
file, so two cameras do not share one; press enter to skip it:

```bash
./pack.sh YMF46D                       # asks for an IP; enter = shared store
CAM_IP=192.0.2.10 ./pack.sh YMF46D   # no prompt
```

The password is generated once per camera and reused, so there is nothing to
sync between a build and the tools.

**YM500L has a size gate.** The vendor updater rejects an image whose rootfs is
larger than stock, so keep `rootfs_size <= 9,113,600`. `ROOTFS_PAD_MULT=65536`
rounds the rootfs to a 64 KiB multiple (139 × 64 KiB = 9,109,504), which is
harmless and matches the geometry known to flash, but alignment itself is not
required — stock is unaligned. See `builds/YM500L/CHANGELOG.txt` for how that
was established.

## Keeping personal data out of a public repo

`tools/pii_check.py` is the gate, and the `pre-push` hook runs it automatically:

```bash
python3 tools/pii_check.py            # tracked files
python3 tools/pii_check.py --staged   # what you are about to commit
python3 tools/pii_check.py --history  # every revision (slow, thorough)
```

It detects by **shape** — RFC1918 addresses outside doc space, non-allowlisted
emails, password-looking assignments — plus exact matches on anything listed in
`tools/.pii_needles` (gitignored, holds your real values). Vendor factory
defaults are whitelisted: `mainctrl` and friends ship the same fixed LAN
addressing on every unit the vendor ever built, so that is the firmware under
study, not your network.

Bypass deliberately with `git push --no-verify`.

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
auto-increment).

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

## Monitoring (Nagios)

Custom builds expose a redacted telemetry feed for monitoring:

```
https://<cam>/nagios.txt     ->  JSON, refreshed every 10s by /opt/ch/nagios.sh
```

Check it with the bundled plugin:

```bash
tools/check_anjoy_nagios.py --host 192.0.2.10 \
    --state-file /var/tmp/check_anjoy_cam.json \
    --stale 90 --warn-temp 75 --crit-temp 85
# OK - heartbeat 41->42 | temperature=71;75;85;0;100 cpu=46;85;95;0;100 ...
```

Two things about this feed are non-obvious and worth knowing:

**It is redacted.** `hwinfo.txt` (the web UI diagnostics panel) carries
reconnaissance-grade fields — MAC, IP addresses, gateway, `PATH`, the process
list, and which busybox applets are missing. That is fine for an operator
viewing their own page. `nagios.txt` deliberately omits all of it and keeps only
health metrics, because it is polled continuously by a machine and may be logged
or cached upstream.

**The HTTP status code is useless here.** The vendor `web_server` returns
`HTTP 200` for a *missing* `.txt` file (`Content-Length: 0`), and its f404
handler also returns 200. A naive `check_http` would report OK forever after the
on-device generator died. Liveness is therefore derived from a **heartbeat
counter and `boot_id` inside the payload**, with the plugin keeping server-side
state. Do not replace this plugin with `check_http`.

The feed is unauthenticated — the vendor static handler has no auth at all, and
this cannot be changed from the outside. Phase 2 (see `todo.md`) adds a real
authenticated `/cgi-bin/nagios` route via an `LD_PRELOAD` shim gated by the
vendor's own `cgi_is_valid_uid_or_username`, so a dedicated `nagios` user
created in the manage-user UI controls access.

## Files

- `extract.sh` — unpack the firmware
- `pack.sh` — repack the firmware
- `todo.md` — open work: the unauthenticated-CGI security audit, and Nagios phase 2
- `tools/anjoy.py` — the unpack/repack engine (layout, CRC, squashfs params)
- `tools/inspect.py` — dump/inspect the container layout
- `tools/dis.py` — capstone helper used to reverse `libtools.so`
- `tools/disfunc.py` — disassemble one function by symbol, resolving literal-pool
  strings and PLT call targets (ARM + Thumb)
- `tools/cgi_routes.py` — dump the vendor `/cgi-bin/` route table (65 routes)
- `tools/check_anjoy_nagios.py` — Nagios plugin for the `nagios.txt` feed
- `tools/ctl3.exp` — run one command on the device over recovery telnet
- `tools/hwdebug.exp` — scripted device diagnostics
- `tools/verify_flash.sh` — confirm a custom rootfs actually landed
- `tools/cam` — get a camera address (argument, `$CAM_IP`, or prompt)
- `tools/camhost.tcl` — the same, for the expect scripts
- `tools/pii_check.py` — the PII gate (worktree / `--staged` / `--history`)
- `tools/install_hooks.sh` — symlink `tools/hooks/*` into `.git/hooks`
- `tools/hooks/pre-push` — runs `pii_check.py` before anything is pushed

## Caveats

- Keep the device-name string at `0x128` matching your model or the updater
  may reject the image.
- If you bump the version, update it in the header name and in the UI /
  `version.txt` so the device does not treat it as same-or-older.
- Flash at your own risk; test on a device you can recover.
