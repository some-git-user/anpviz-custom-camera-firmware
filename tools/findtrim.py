#!/usr/bin/env python3
"""Find a trim that lands BELOW stock rootfs size (8,962,048 B) so the
updater's 'size bigger than' gate cannot reject it."""
import os, re, shutil, subprocess

SRC = os.environ.get("ROOTFS", "builds/YMF46D/rootfs")
STOCK = 8962048
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

KO   = ["opt/ch/unicode_16x16-ko.font", "opt/ch/unicode_16x16-ko.font.codecmap"]
WASM = ["var/www/lib/libffmpeg.wasm"]
ZBAR = ["opt/ch/zbarscan"]

variants = [
    ("EN only + ko + wasm",                 r"^English\.txt$",        KO + WASM),
    ("EN only + ko + wasm + zbarscan",      r"^English\.txt$",        KO + WASM + ZBAR),
    ("EN+DE + ko + wasm + zbarscan",        r"^(English|German)\.txt$", KO + WASM + ZBAR),
    ("EN+DE+CN+RU + ko + wasm + zbarscan",  r"^(English|German|SimpChinese|Russian)\.txt$", KO + WASM + ZBAR),
    ("ALL langs + ko + wasm + zbarscan",     None,                    KO + WASM + ZBAR),
    ("ALL langs + wasm + zbarscan",          None,                    WASM + ZBAR),
]

print("stock rootfs = %d bytes\n" % STOCK)
print("%-40s %10s %12s  %s" % ("VARIANT", "SIZE", "vs STOCK", "VERDICT"))
best = None
for name, langs, rem in variants:
    s = build(langs, rem)
    ok = s < STOCK
    print("%-40s %10d %+11d  %s" % (name, s, s - STOCK,
          "OK - below stock" if ok else "REJECT - above stock"))
    if ok and (best is None or s > best[1]):
        best = (name, s, langs, rem)

if best:
    print("\nLARGEST-BELOW-STOCK CHOICE: %s  (%d bytes, %d spare)"
          % (best[0], best[1], STOCK - best[1]))
else:
    print("\nNo variant fits below stock.")
