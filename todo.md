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

### Phase 2 — `/cgi-bin/nagios` via LD_PRELOAD shim (proper fix)

The CGI route table is **compiled in** — `InitHttpCgi` reads flag files but no
route config, so a new route must be injected.

Confirmed viable:
- `http_cgi_find` is **PLT-interposable** (`R_ARM_JUMP_SLOT` @ `0x8b6ac`,
  `.rel.plt` -> `.got`).
- `LD_PRELOAD` **is** supported by the device's `ld-uClibc-1.0.31`.
- `rcS` already exports `LD_LIBRARY_PATH`, so the env propagates to `web_server`
  via `procman`.
- Handler calls `cgi_is_valid_uid_or_username()` -> **real manage-user auth**.
  Create a `nagios` account in the existing UI; revocable from the UI.
- Served over the existing **HTTPS**, proper `application/json`, real `404`.

Toolchain (no root required):
```
https://toolchains.bootlin.com/downloads/releases/toolchains/armv7-eabihf/tarballs/armv7-eabihf--uclibc--stable-2024.05-1.tar.xz
```
Device is `armv7-eabihf`, **hard-float** (`VFPv3-D16`, `Tag_ABI_VFP_args: VFP
registers`), uClibc 1.0.31. Debian's glibc `gcc-arm-linux-gnueabihf` will **not**
produce dynamically linked binaries that load here; a `-static` build sidesteps it.

**Risk:** a crashing shim takes down `web_server`, and the telnet toggle is itself
web-controlled, making remote recovery awkward. Mitigate by gating the preload
behind a flag file and testing with the device physically in hand.

---

## 4. Deferred / nice-to-have

- [ ] Port the Nagios endpoint to `YM500L` (different squashfs block size,
      different TLS story — nothing ports automatically).
- [ ] Push branch to a remote (blocked: no SSH key configured).
- [ ] Audit whether `/cgi-bin/getuid` rate-limits failed attempts.
- [ ] Consider whether `hwinfo.txt` should also be redacted (it currently leaks
      the same recon fields to the whole LAN).
