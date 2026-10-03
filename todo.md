# TODO

Findings verified on device `192.0.2.10` (YMF46D, custom1) on 2026-10-03.
Everything below was measured, not assumed.

---

## 1. SECURITY AUDIT — unauthenticated CGI surface

**Priority: HIGH. Independent of the Nagios work; should be done regardless.**

The vendor `web_server` (gSOAP 2.8 + `libcgibin_curl.so`) exposes **65 CGI routes**
under `/cgi-bin/`. The CGI layer has **no framework-level authentication** — each
handler individually opts in by calling `cgi_is_valid_uid_or_username()`.
Handlers that forget to are wide open.

Confirmed open with **zero credentials**:

```
GET /cgi-bin/getinfo?type=1
  -> 200  <info model="MCF46D" oem_model="YMF46D_IR_5MP"
           mac_address="REDACTED_MAC"/>
```

That is the hardware MAC and the OEM model string, handed out to anything on the LAN.

### What still needs auditing

For **every** route in the table, determine: does it authenticate once its
parameters parse correctly? A `400 parse parameters` response tells us nothing —
it means we never got far enough to reach the auth check.

Dump the current table with:

```sh
python3 tools/cgi_routes.py
```

Routes to prioritise (highest impact if unauthenticated):

| Route | Why it matters |
|---|---|
| `/cgi-bin/reboot`, `/cgi-bin/rebootipc` | Reboot the camera |
| `/cgi-bin/factory_reset`, `/cgi-bin/factoryipc` | Wipe configuration |
| `/cgi-bin/flash_eraseall` | Destroy flash |
| `/cgi-bin/user_management` | Create/modify/delete users |
| `/cgi-bin/getCurrentUserAccount` | Current session identity |
| `/cgi-bin/console.cgi` | Shell-ish (`cgi_open_slogtcp`) |
| `/cgi-bin/setDeviceName`, `/cgi-bin/network` | Persistent config writes |
| `/cgi-bin/set_service_port` | Move the listening port |
| `/cgi-bin/umount_nfs` | Storage disruption |
| `/cgi-bin/getmacaddr_eth0.cgi` | MAC disclosure |
| `/cgi-bin/settings/system/*` | Version/serial disclosure |

Record results in `tools/cgi_audit_results.md` as a table:
`route | params needed | auth? | data leaked | severity`.

Useful helper: `tools/disfunc.py <lib> <symbol>` disassembles a handler and
resolves its string references — look for a `cgi_is_valid_uid_or_username` call.

**Note:** `/cgi-bin/getuid?username=X&password=Y` is a **credential oracle** —
it validates against the manage-user DB and returns `password error` on failure.
Check whether it rate-limits; if not, it enables offline-style password guessing.

---

## 2. Static file handler — known bad behaviours (documented, not fixable)

Verified, and relevant to anything we serve:

- **Static files have NO auth at all.** `GET /hwinfo.txt` -> `200` with no creds.
  `Basic`/`Digest` headers are ignored on the static path.
- **Extension whitelist** is only `.gif .htm .jpeg .png .svg .txt` (+ `.ini`,
  `.pdf`). No `.json` — unknown extensions fall through to the f404 handler.
- **A missing `.txt` still returns `200 text/plain` with `Content-Length: 0`.**
  This is the important one: **HTTP status cannot detect a dead generator.**
  Any monitoring payload must carry its own heartbeat timestamp.
- `/var/www` is **read-only squashfs**. Only `/tmp` and `/mnt/nand` are writable,
  so generated content must live in `/tmp` and be symlinked into the web root.
- `busybox httpd` is a **dangling symlink** — the applet is not compiled in.
  Also absent: `nc`, `iptables`, `bash`, `openssl`, `snmpd`, `nrpe`, `xinetd`.
  No firewall or secondary web server available.
- Vendor password hashes are **salted/unknown** (plain MD5 of known passwords does
  not match `EncryptPwd` in `/mnt/nand/config.xml`). We cannot verify a password
  in a shell script — only the vendor binaries can.

**HTTPS works for static content** with our own cert (`CN=homecamera.lan`, valid to
2036), so transport crypto is free for any approach.

---

## 3. Nagios endpoint — plan C (both phases)

### Phase 1 — static `/nagios.txt` (do now, zero risk)

Same pattern as `hwinfo.txt`: a generator writes `/tmp/nagios.txt`, symlinked to
`/var/www/nagios.txt`. No new binaries, no toolchain, no injected code.

Requirements:
- **Redacted payload.** Drop `mac`, `ip_addrs`, `default_route`, `path`,
  `top_processes`, `cmd_probe`, `soc_id`. Monitoring needs none of them, and they
  are exactly the reconnaissance-value fields.
- **Mandatory heartbeat** (`generated` epoch + seconds) inside the payload, because
  a stale/missing file still returns HTTP 200.
- Nagios plugin parses the JSON and **fails on staleness**, not on HTTP code.
- Unauthenticated — acceptable only because it is redacted and LAN-scoped.

### Phase 2 — `/cgi-bin/nagios` via LD_PRELOAD shim — DONE

Shipped as `tools/nagios_shim/nagios_authd.c` -> `builds/YMF46D/rootfs/opt/ch/nagios_authd.so`,
preloaded in `rcS` on the `procman` line only. Build with `tools/nagios_shim/build_shim.sh`.

**Verified ABI** (empirically, not static guess) — `http_cgi_bin` calls:
```
http_cgi_find(uri, r1, table_off) -> nonzero if route registered   [GATE]
http_cgi_handle(uri, out, client_ip)                              [DISPATCH]
   out = calloc(1, 102400)   // safe to sprintf our body
   returns HTTP status; caller sends `out` as the body
```
The shim interposes BOTH:
- `http_cgi_find` returns 1 for `/cgi-bin/nagios` (the route is NOT in the
  vendor table, so without this the dispatcher never runs -> 404).
- `http_cgi_handle` serves the authenticated feed; every other route is
  forwarded to the real function unchanged.

**Auth** reuses the device's own user DB (the web "manage user" UI writes
`<UserConfig>` in `/mnt/nand/config.xml`):
```
GET /cgi-bin/nagios?nagios_user=<u>&nagios_pass=<p>
  cgi_get_value(uri, "nagios_user"/"nagios_pass", ...)   // RAW, NOT urldecoded
  url_decode() in the shim                               // REQUIRED
  MsgUserGetPassword(user, stored) -> 0 + stored PLAINTEXT
  constant-time compare(pass, stored)
  serve /tmp/nagios.txt -> 200
```
`cgi_is_valid_username_password` was tried and ABANDONED: it needs a
request-context object not available at this layer, and its `username` param
substring-collides with `cgi_is_valid_uid_or_username` (order-sensitive).

**Verified on device** (192.0.2.10): no-creds 403, wrong-pass 403,
unknown-user 403, correct-creds 200+feed, control `getinfo` 200 (passthrough
intact). Audit trail in `/tmp/nagios_auth.log` (client IP + verdict, no creds).
**FAIL CLOSED** on: missing auth helper, null outbuf, missing creds, unknown
user, bad pass, unreadable feed.

**Persistence**: `rcS` sets `LD_PRELOAD=/opt/ch/nagios_authd.so` on the
`procman` line only. `procman` uses `execve(__environ)`, so the preload
propagates to the `web_server` it spawns and its respawn children. Scoped so
no other boot process is affected; the shim exports only the two CGI symbols
so it is inert everywhere else. If the `.so` is missing the `[ -f ]` guard
runs stock `procman` (harmless no-op).

**Gotchas recorded**:
- `cgi_get_value` does NOT urldecode — the shim must, or a password with `%xx`
  never matches. Verified `REDACTED_WEB_PASSWORD` -> `REDACTED_WEB_PASSWORD`.
- The CGI route is served `Content-Type: text/xml` even though the body is
  JSON; the Nagios plugin parses JSON regardless of declared type.
- `procman` feeds the hardware watchdog — `killall procman` can trip a reboot.
  Test by starting a second `procman` with the preload, or flash and reboot.

**Packed image**: `out/YMF46D_3.4.5.2-custom3.bin`, rootfs 8,978,432 B
(ceiling 9,355,264). Verified `nagios_authd.so` + `rcS` preload inside.

### Phase 3 — recording-volume (SD card) metric, feed schema 2 — DONE (pending build)

**The gap**: schema 1's only disk metric was `nand_used_pct` / `nand_avail_kb` --
that is the **1 MB jffs2 config partition**, not the disk your video goes to.
The recording volume was not reported at all, so a full or missing SD card (by
far the most likely storage failure on a dashcam) was invisible to monitoring.

**New fields** (`/opt/ch/nagios.sh`, first mounted volume, probed
`mmc0` -> `mmc1` -> `usb`):

| field | meaning |
|---|---|
| `rec_storage_present` | 1/0 |
| `rec_storage_slot` | `mmc0` / `mmc1` / `usb` / `none` |
| `rec_storage_total_kb` | `df` 1K-blocks |
| `rec_storage_used_kb` | `df` used |
| `rec_storage_avail_kb` | `df` available |
| `rec_storage_used_pct` | `df` use% |

Slot **label** only -- no device node or mount path, keeping the feed redacted.
Absent card emits explicit JSON `null`s so "no card" != "card but unreadable".
Added `mountpoint_ok()` (no `mountpoint` applet in this busybox; parse `mount`).
`SCHEMA` 1 -> 2.

**Checker** (`tools/check_anjoy_nagios.py`): `--warn-rec 90` / `--crit-rec 97`
/ `--ignore-no-card`.

```
no card mounted                  -> CRITICAL   (nothing is recording)
used >= --crit-rec               -> CRITICAL
used >= --warn-rec               -> WARNING
< 5 MB free at a low percentage  -> WARNING    (huge-card edge case)
mounted but df unreadable        -> UNKNOWN
field absent (schema < 2)        -> UNKNOWN
```

**Verified on device** (192.0.2.10):
- absent -> `present:0 slot:none nulls`; checker CRITICAL, and OK with
  `--ignore-no-card`
- present -> bind-mounted the jffs2 partition onto `/mnt/mmc0` to get real `df`
  numbers (total 1024 / used 260 / avail 764 / 25%); checker reported
  `rec_storage(mmc0) only 764 KB free` = WARNING, proving the absolute-headroom
  path E2E through the authenticated CGI route.
- tmpfs quirk: this busybox reports **0 blocks for tmpfs**. The checker treats a
  zero/absent total as *unreadable* (UNKNOWN), not "0 KB free" -- avoids a false
  alarm on any pseudo-fs.
- schema-1 fail-safe: pointed the new checker at the still-flashed custom3 device
  and it correctly returned `rec_storage state unknown (generator schema <2?)`
  instead of silently passing.
- 14 fixture combinations (6 payload shapes x default/`--ignore-no-card`) all
  return the expected exit codes.

**Note**: `/opt` is squashfs (read-only) at runtime, so testing required running
the generator from `/tmp`. The change ships via `pack.sh` like everything else.

---

## 4. Deferred / nice-to-have

- [x] **FLASH-VERIFIED (cold boot, custom3) — ALL GREEN.** Device rebooted on
      `custom3`; the boot-spawned `web_server` has `nagios_authd.so` mapped
      (3 segments) and `procman`'s environ carries `LD_PRELOAD`. Auth matrix
      over **both HTTP and HTTPS**: no-creds 403, wrong-pass 403, unknown-user
      403, correct-creds 200 + live JSON feed (real generator: heartbeat
      advancing, temp/mem/nand populated). `getinfo` passthrough 200. Audit
      log `/tmp/nagios_auth.log` shows the correct verdicts. The Nagios plugin
      returns OK with full perfdata and detects heartbeat advance. Persistence
      via `rcS` confirmed working from flash.
      NOTE: `pack.sh` regenerates `reclogin.pass` each build — after flashing,
      copy `builds/YMF46D/rootfs/opt/ch/reclogin.pass` to `tools/.reclogin_pass`
      so `tools/ctl3.exp` can log in.
- [ ] Create a dedicated low-privilege `nagios` account in the web UI rather
      than reusing `camera`; scope it read-only if the UI allows.
- [ ] **Build + flash `custom4`** so the schema-2 recording-volume fields actually
      ship. Until then the checker reports `rec_storage state unknown` against the
      live device (correct fail-safe, but the metric is not yet in the field).
- [ ] With a **real SD card** inserted, confirm the vendor mounts the recording
      volume at `/mnt/mmc0` (not somewhere else) and that `df` reports real vfat
      numbers. Slot probe order `mmc0`/`mmc1`/`usb` is inferred from `hwinfo.sh`
      and the mount dirs, not observed with a card present.
- [ ] Port the Nagios endpoint to `YM500L` (different squashfs block size,
      different TLS story — nothing ports automatically).
- [ ] Push branch to a remote (blocked: no SSH key configured).
- [ ] Audit whether `/cgi-bin/getuid` rate-limits failed attempts.
- [ ] Consider whether `hwinfo.txt` should also be redacted (it currently leaks
      the same recon fields to the whole LAN).
