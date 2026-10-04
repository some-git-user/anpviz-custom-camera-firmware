# TODO — firmware security + monitoring findings

Findings verified on the bench units. Everything below was measured, not assumed.

---

## 1. SECURITY AUDIT — unauthenticated CGI surface

**Priority: HIGH.**

The vendor `web_server` (gSOAP 2.8 + `libcgibin_curl.so`) exposes **65 CGI routes**
under `/cgi-bin/`. The CGI layer has **no framework-level authentication** — each
handler individually opts in by calling `cgi_is_valid_uid_or_username()`.
Handlers that forget to are wide open.

Confirmed open with **zero credentials**:

```
GET /cgi-bin/getinfo?type=1
  -> 200  <info model="MCF46D" oem_model="YMF46D_IR_5MP"
           mac_address="<unit MAC, redacted>"/>
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

- [ ] Audit whether `/cgi-bin/getuid` rate-limits failed attempts.
- [ ] Work the priority table above and record results in
      `tools/cgi_audit_results.md`.

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

**HTTPS works for static content** with our own cert (`CN=homecamera.lan`), so
transport crypto is free for any approach.

- [ ] Consider whether `hwinfo.txt` should also be redacted (it currently leaks
      the same recon fields to the whole LAN).

---

## 3. Nagios endpoint — design

### Phase 1 — static `/nagios.txt`

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

### Phase 2 — `/cgi-bin/nagios` via LD_PRELOAD shim

Shipped as `tools/nagios_shim/nagios_authd.c` -> `opt/ch/nagios_authd.so`,
preloaded in `rcS` on the `procman` line only.

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

**Auth matrix** (verified over both HTTP and HTTPS): no-creds 403, wrong-pass 403,
unknown-user 403, correct-creds 200 + feed, control `getinfo` 200 (passthrough
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
- `cgi_get_value` does NOT urldecode — the shim must, or a password containing
  a `%xx` sequence never matches.
- The CGI route is served `Content-Type: text/xml` even though the body is
  JSON; the Nagios plugin parses JSON regardless of declared type.
- `procman` feeds the hardware watchdog — `killall procman` can trip a reboot.
  Test by starting a second `procman` with the preload, not by killing the
  running one.

### Phase 3 — recording-volume (SD card) metric, feed schema 2

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

**Verified on device**:
- absent -> `present:0 slot:none nulls`; checker CRITICAL, and OK with
  `--ignore-no-card`
- present -> bind-mounted the jffs2 partition onto `/mnt/mmc0` to get real `df`
  numbers; checker reported the low-headroom WARNING, proving the absolute-free
  path end to end through the authenticated CGI route.
- tmpfs quirk: this busybox reports **0 blocks for tmpfs**. The checker treats a
  zero/absent total as *unreadable* (UNKNOWN), not "0 KB free" -- avoids a false
  alarm on any pseudo-fs.
- schema-1 fail-safe: the checker returns `rec_storage state unknown
  (generator schema <2?)` instead of silently passing.
- 14 fixture combinations (6 payload shapes x default/`--ignore-no-card`) all
  return the expected exit codes.

**Note**: `/opt` is squashfs (read-only) at runtime, so testing requires running
the generator from `/tmp`.

---

## 4. Platform findings + open questions

### Nagios access control
- [ ] Create a dedicated low-privilege `nagios` account in the web UI rather
      than reusing `camera`; scope it read-only if the UI allows.
- [ ] **YM500L: Nagios AUTH cannot port as-is.** `web_server` here is glibc AND
      stripped (487 FUNC exports but no CGI dispatch hooks —
      no `http_cgi_find`/`http_cgi_handle`/`MsgUserGetPassword`). The
      LD_PRELOAD shim has nothing to interpose. **Gating the world-readable feed
      is not possible on this model.** Options are an unauthenticated redacted
      LAN feed, or a separate auth task.

### Recording volume
- [ ] With a **real SD card** inserted, confirm the vendor mounts the recording
      volume at `/mnt/mmc0` (not somewhere else) and that `df` reports real vfat
      numbers. Slot probe order `mmc0`/`mmc1`/`usb` is inferred from `hwinfo.sh`
      and the mount dirs, not observed with a card present.

### YM500L platform (glibc, INFINITY3 MSC000A-S04A, kernel 3.18.30)
- **Temperature sensor**: the ONLY path is
  `/sys/devices/system/cpu/cpufreq/temp_out` (format `Temp=NN`).
  `TEMP_R` / `thermal_zone0` do NOT exist on this SoC.
- **Device nodes need the `/dev/block/` prefix**: `/dev/block/mtdblock2`
  (squashfs @ `/system`), `mtdblock4` (`/mnt/nand` jffs2), `mtdblock5`
  (`/tmp/oem`). Bare `/dev/mtd*` does not exist.
- **busybox reality**: the tree ships 339 symlinks but the runtime binary has
  only ~110 applets. **MISSING: `head`, `tr`, `uniq`, `stat`, `readlink`,
  `mountpoint`, `nc`.** Use `busybox awk 'NR<=N'` instead of `head -N`.
- **`ps -o comm` is NOT supported** — it exits `ps: invalid option -- 'o'`,
  which silently blanks `top_processes` to `n/a`. Read `/proc/<pid>/comm`
  instead; portable to YMF46D too.
- **Telnet recovery shell** is opt-in via the Service Ports -> Telnet checkbox,
  which drives the spare `enable_tst` attribute. The checkbox lives on the
  `StreamingMediaConfig` (Service Ports) page, not a "Port" tab.
  `/setMediaStreamConfig` persists `enable_tst` and a normal Save preserves it
  (the page only `setAttribute()`s fields it knows about).
- [ ] **This unit runs genuinely hot: ~89-90 C at idle.** Confirmed after
      killing all test load — not an artifact of test processes. Remaining CPU
      is vendor `media_server` (~40% of one core). `temp_out` may be
      uncalibrated, so treat as a trend.
- [ ] `default_route` reports the gateway as **the device's own address** rather
      than a real upstream gateway. Verified against `/proc/net/route` — this is
      a **vendor quirk, not a parsing bug**. YMF46D reports a real gateway
      instead. Do not "fix".
