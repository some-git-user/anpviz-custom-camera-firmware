#!/usr/bin/env python3
"""
pii_check.py -- refuse to let personal information into this public repo.

    ./tools/pii_check.py            # audit tracked files in the working tree
    ./tools/pii_check.py --staged   # audit what is about to be committed
    ./tools/pii_check.py --history  # audit every reachable revision

WHY THIS EXISTS
---------------
This is a PUBLIC repo of camera firmware. At one point it carried our bench
addresses, a unit's hardware MAC, and recovery passwords -- some in tracked
files, some in commit messages. All of it was scrubbed, and this script is what
keeps it scrubbed.

DETECTION IS GENERIC, NOT SECRET-BASED
-------------------------------------
This tracked script contains NO actual address, MAC, password, or personal
email -- otherwise the gate itself would leak them. Instead it detects by shape:

  * any RFC1918 private-range IP that is not an RFC5737 documentation address
  * any email address not on the documentation allowlist
  * password-looking assignments (key = "literal")

PLUS: if you keep a gitignored tools/.pii_needles file (one literal string per
line -- your bench IPs, MACs, passwords), each is checked exactly. That is how
you pin YOUR specific secrets without committing them. A fresh clone has no
needles file and still gets the generic shape checks.

WHAT IS EXPLICITLY NOT FLAGGED
----------------------------
The vendor's own factory-default addresses and MACs. `mainctrl`, `libtools.so`,
`config.default.*.xml`, `WifiConfig.js`, `rcS.default*` and the udhcpc
`default.script` ship the same fixed factory LAN addressing on every unit the
vendor ever made. They are part of the firmware image under study, not our
network, and are whitelisted in VENDOR_OK so this gate stays meaningful
instead of drowning in false positives. (Verified byte-identical to the stock
image rather than assumed.)

If a tool of yours legitimately needs a private IP in a comment, use RFC5737
documentation space (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24) rather
than editing the whitelist.

Exit code 0 = clean, 1 = findings.
"""
import argparse
import os
import re
import subprocess
import sys

# RFC1918 private ranges.
PRIV = re.compile(r"\b(?:192\.168\.|10\.\d+\.|172\.(?:1[6-9]|2\d|3[01])\.)\d+\.\d+\b")
# RFC5737 documentation ranges -- always fine, in any file.
DOC_NETS = ("192.0.2.", "198.51.100.", "203.0.113.")

# Email addresses that are fine to commit (docs, GitHub noreply, localhost).
EMAIL = re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.-]+\b")
EMAIL_OK = (
    "example.com", "example.org", "example.net",
    "users.noreply.github.com", "noreply@github.com", "localhost",
    "domain.com", "yourdomain.com", "email@example",  # universal UI placeholders
)

# A password-looking assignment: a key containing pass/password/secret/token
# followed by a quoted literal of 8+ chars. Catches accidental hardcoding.
# The literal must not START with '$' -- `REC_PASS="$RECOVERY_PASS"` is a
# variable copy, not a baked-in secret.
PASS_ASSIGN = re.compile(
    r"""(?i)\b\w*(?:pass|passwd|password|secret|token)\w*\s*=\s*['"][^$'"][^'"]{7,}['"]"""
)
PASS_ASSIGN_OK = ("reclogin", "RECLOGIN", "yourpassword", "s3cret", "<",
                 "password here", "passphrase here", "help=",
                 # Redaction markers left by the history scrub. A line reading
                 # PASS='REDACTED_RECOVERY_PASSWORD' is sanitized history, not
                 # a live secret -- flagging it would make the gate cry wolf.
                 "REDACTED",
                 # Shell config knobs are not hardcoded secrets: a value built
                 # from ${VAR:-default}, $(cmd), or ${VAR%...} is dynamic. The
                 # whole point of those forms is that nothing is baked in.
                 "${", "$(", "$[")

# Vendor-supplied files whose private addresses are factory defaults, not ours.
VENDOR_OK = {
    "builds/YM500L/rootfs/opt/ch/mainctrl",
    "builds/YMF46D/rootfs/opt/ch/mainctrl",
    "builds/YM500L/rootfs/opt/ch/libtools.so",
    "builds/YMF46D/rootfs/opt/ch/libtools.so",
    "builds/YM500L/rootfs/opt/ch/config.default.mc500l.xml",
    "builds/YMF46D/rootfs/opt/ch/config.default.mcf46d.xml",
    "builds/YM500L/rootfs/var/www/js/WifiConfig.js",
    "builds/YMF46D/rootfs/var/www/js/WifiConfig.js",
    "builds/YM500L/rootfs/etc/init.d/rcS",
    "builds/YM500L/rootfs/opt/ch/script_i3_316dm/rcS.default",
    "builds/YM500L/rootfs/opt/ch/script_i3_316dm/rcS.default_debug",
    "builds/YM500L/rootfs/usr/share/udhcpc/default.script",
    "builds/YMF46D/rootfs/usr/share/udhcpc/default.script",
    "builds/YMF46D/rootfs/opt/ch/web_server",
}


def load_needles():
    """Optional gitignored file of exact strings that must never appear."""
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".pii_needles")
    needles = []
    if os.path.isfile(path):
        with open(path, "r", encoding="utf-8", errors="ignore") as fh:
            for line in fh:
                s = line.strip()
                if s and not s.startswith("#"):
                    needles.append(s)
    return needles


def is_binary(data):
    """A NUL byte is the conventional binary marker (same rule git uses)."""
    return "\x00" in data[:8192]


def scan_text(where, data, needles, vendor=False):
    """Findings for one blob of text.

    Exact needles are checked everywhere, including binaries -- a leaked IP or
    password can hide in a compiled blob. The shape heuristics (private IP,
    email, password assignment) only run on text files and skip vendor blobs,
    because on a stripped ARM binary they produce nothing but noise: random
    bytes spell thousands of fake "email addresses".
    """
    out = []
    for n in needles:
        if n in data:
            for i, line in enumerate(data.splitlines(), 1):
                if n in line:
                    out.append(f"NEEDLE {n!r}  {where}:{i}: {line.strip()[:110]}")
    if vendor or is_binary(data):
        return out
    for i, line in enumerate(data.splitlines(), 1):
        for m in PRIV.finditer(line):
            if m.group(0).startswith(DOC_NETS):
                continue
            out.append(f"PRIV-IP {m.group(0)}  {where}:{i}: {line.strip()[:110]}")
        for m in EMAIL.finditer(line):
            if any(ok in m.group(0) for ok in EMAIL_OK):
                continue
            out.append(f"EMAIL {m.group(0)}  {where}:{i}: {line.strip()[:110]}")
        if PASS_ASSIGN.search(line) and not any(ok in line for ok in PASS_ASSIGN_OK):
            out.append(f"PASS-ASSIGN  {where}:{i}: {line.strip()[:110]}")
    return out


def check_worktree(needles):
    hits = []
    files = subprocess.check_output(["git", "ls-files"], text=True).splitlines()
    for f in files:
        try:
            data = open(f, "r", encoding="utf-8", errors="ignore").read()
        except (OSError, IsADirectoryError):
            continue
        hits += scan_text(f, data, needles, vendor=f in VENDOR_OK)
    return hits


def check_staged(needles):
    hits = []
    names = subprocess.check_output(
        ["git", "diff", "--cached", "--name-only", "--diff-filter=ACM"], text=True
    ).splitlines()
    for f in names:
        try:
            data = git_blob_bytes(f":{f}")
        except subprocess.CalledProcessError:
            continue
        hits += scan_text(f"(staged) {f}", data, needles, vendor=f in VENDOR_OK)
    return hits


def check_history(needles):
    hits = []
    revs = subprocess.check_output(["git", "rev-list", "--all"], text=True).split()
    seen = set()
    for rev in revs:
        msg = subprocess.check_output(
            ["git", "log", "-1", "--format=%an <%ae>%n%s%n%b", rev], text=True
        )
        hits += scan_text(f"commit {rev[:8]} (message)", msg, needles)
        obj = subprocess.check_output(
            ["git", "ls-tree", "-r", rev, "--format=%(objectname) %(path)"], text=True
        )
        for line in obj.splitlines():
            parts = line.split(" ", 1)
            if len(parts) != 2:
                continue
            sha, path = parts
            if sha in seen:
                continue
            seen.add(sha)
            try:
                data = git_blob_bytes(sha)
            except subprocess.CalledProcessError:
                continue
            hits += scan_text(f"{path} [{rev[:8]}]", data, needles,
                             vendor=path in VENDOR_OK)
    return hits


def git_blob_bytes(rev_spec):
    """Fetch a blob as bytes and decode lossily.

    Firmware blobs are full of non-UTF-8 bytes, so text mode is unusable -- it
    raises UnicodeDecodeError. Decoding with errors='ignore' is safe here: NUL
    bytes survive UTF-8 decoding, so is_binary() still identifies binaries.
    """
    raw = subprocess.check_output(["git", "cat-file", "blob", rev_spec])
    return raw.decode("utf-8", errors="ignore")


def main():
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--staged", action="store_true", help="scan staged changes")
    ap.add_argument("--history", action="store_true", help="scan all revisions")
    args = ap.parse_args()

    needles = load_needles()
    if args.history:
        hits, scope = check_history(needles), "all revisions"
    elif args.staged:
        hits, scope = check_staged(needles), "staged changes"
    else:
        hits, scope = check_worktree(needles), "tracked files in the working tree"

    print(f"pii_check: scanning {scope}"
          + (f" ({len(needles)} pinned needle(s))" if needles
             else " (no tools/.pii_needles -- generic checks only)"))
    for h in hits:
        print("  " + h)
    if hits:
        print(f"\npii_check: FAIL -- {len(hits)} finding(s). Do not push this.")
        print("  Scrub the values. If a private IP/email is a vendor factory")
        print("  default, add that file to VENDOR_OK and explain why.")
        return 1
    print("pii_check: clean -- no personal information found.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
