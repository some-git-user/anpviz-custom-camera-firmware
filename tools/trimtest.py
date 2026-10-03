#!/usr/bin/env python3
"""Measure squashfs size for trim variants (data-only, no binary removal)."""
import os, re, shutil, subprocess, sys

SRC = os.environ.get("ROOTFS", "builds/YMF46D/rootfs")
STOCK = 8962048
LIM = 0x900000  # 9 MiB guess at rootfs partition
EPOCH = "1673337341"

def build(keep_langs, remove, out="/tmp/tt.sq"):
    tmp = "/tmp/tt"
    shutil.rmtree(tmp, ignore_errors=True)
    shutil.copytree(SRC, tmp, symlinks=True)
    langdir = os.path.join(tmp, "var/www/custom_lang")
    if os.path.isdir(langdir) and keep_langs is not None:
        pat = re.compile(keep_langs)
        for f in os.listdir(langdir):
            if not pat.match(f):
                os.unlink(os.path.join(langdir, f))
    for f in remove:
        p = os.path.join(tmp, f)
        if os.path.exists(p):
            os.unlink(p)
    if os.path.exists(out):
        os.unlink(out)
    env = dict(os.environ, SOURCE_DATE_EPOCH=EPOCH)
    subprocess.run(["mksquashfs", tmp, out, "-comp", "xz", "-b", "262144",
                   "-noappend", "-no-xattrs", "-all-root", "-no-progress"],
                   check=True, env=env, stdout=subprocess.DEVNULL)
    return os.path.getsize(out)

KO = ["opt/ch/unicode_16x16-ko.font", "opt/ch/unicode_16x16-ko.font.codecmap"]
WASM = ["var/www/lib/libffmpeg.wasm"]

variants = [
    ("keep EN+DE, drop ko-font",            r"^(English|German)\.txt$", KO),
    ("keep EN+DE, drop ko-font+wasm",       r"^(English|German)\.txt$", KO + WASM),
    ("keep EN+DE+CN+RU, drop ko-font+wasm", r"^(English|German|SimpChinese|Russian)\.txt$", KO + WASM),
    ("keep ALL langs, drop ko-font+wasm",   None, KO + WASM),
    ("keep ALL langs, drop wasm only",      None, WASM),
]

print("%-42s %10s %12s %12s" % ("VARIANT", "SIZE", "vs STOCK", "vs 9MiB"))
for name, langs, rem in variants:
    s = build(langs, rem)
    tag = "BELOW STOCK" if s < STOCK else ("under 9MiB" if s < LIM else "OVER 9MiB")
    print("%-42s %10d %+11d %+11d   %s" % (name, s, s - STOCK, s - LIM, tag))
