/* ---------------------------------------------------------------------------
 * cve_deny.so -- LD_PRELOAD mitigation for the ANJVISION web_server file-read
 * CVEs on the YM500L (glibc 2.19, armv7 hard-float).
 *
 * WHAT IT CLOSES
 *   CVE-2024-35343  GET /playback/<path>  -> arbitrary file read
 *   CVE-2024-35341  GET /config.xml|/ConfigFile.ini -> config exfiltration
 *
 * WHY CALLER-GATING AND NOT A PLAIN PATH DENY-LIST
 * A path-only deny-list BREAKS THE CAMERA. A live LD_PRELOAD capture of the
 * vendor stack (tools/cve_shim/cve_log.c) shows web_server reading
 * /etc/passwd NINE TIMES during ordinary operation from return address
 * 0x38fc5 -- that is the login/session code. Denying "/etc/passwd" for every
 * caller logs the user out of the product. Same for /mnt/nand/config.xml,
 * which the vendor code reads constantly for normal config operations.
 *
 * The vulnerable handlers are distinguishable by CALLER, so we gate on the
 * return address as well as the path:
 *
 *   0x501a5  the /playback/<path> handler.
 *            Captured opening EXACTLY the four paths probed through
 *            /playback/ and nothing else -- including /tmp/cve_log.txt, which
 *            no other code path ever touches. This address is the handler.
 *   0x500ef  the config-download handler's fopen (config.xml, ConfigFile.ini)
 *   0x500ab  the config-download handler's popen("cp config.xml ConfigFile.ini")
 *
 * Everything else is left completely alone, so normal operation cannot be
 * affected. The gate FAILS OPEN: an unrecognised caller is passed through
 * untouched. A wrong address costs protection, never availability.
 *
 * BUILD-SPECIFIC. These offsets belong to web_server BuildID
 * dde0ea728d826aa040c7afeb442f7a34f642e352 (non-PIE, so the offsets are
 * absolute). pack.sh verifies the BuildID before shipping this; if the vendor
 * binary changes, the offsets are stale and the shim must be re-derived.
 *
 * NO dl*() -- the device's libc.so.6 exports no dlvsym/dlsym (they live in
 * libdl.so.2) while our glibc-2.39 sysroot merged them into libc and records
 * the ref against libc.so.6, so a dlvsym shim dies at load with
 *   "symbol dlvsym, version GLIBC_2.4 not defined in file libc.so.6".
 * Every forward below is a direct, version-pinned symbol reference instead.
 * ------------------------------------------------------------------------ */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* Real implementations on the target, all GLIBC_2.4. _IO_fopen/_IO_popen are
   the actual implementations, NOT thunks back into fopen/popen, so forwarding
   cannot recurse into ourselves. */
extern FILE *_IO_fopen(const char *, const char *);
extern FILE *_IO_popen(const char *, const char *);
extern int openat(int, const char *, int, ...);
extern char *realpath(const char *, char *);

/* system() is a weak alias of a GLIBC_PRIVATE symbol; binding the private name
   lets us interpose `system` without dlvsym. Verified loadable on .113. */
__asm__(".symver libc_system,__libc_system@GLIBC_PRIVATE");
extern int libc_system(const char *);

/* --- vulnerable call sites (web_server, non-PIE absolute addresses) -------- */
/* The /playback/<path> arbitrary-read handler. */
#define RA_PLAYBACK 0x501a5UL
/* The config-download handler: fopen of the config, and the popen that
   copies it into place for serving. */
#define RA_CFGDL_FOPEN 0x500efUL
#define RA_CFGDL_POPEN 0x500abUL

/* resolve() is defined BEFORE the shared logic because deny_for() calls it.
   The host unit test supplies its own stub instead: on the host there is no
   /etc/passwd -> /tmp/passwd symlink, so a real realpath() would not
   reproduce the device topology the tests are about.

   Falls open: if realpath() fails we leave `out` empty and deny_for() then
   matches the raw path, which still covers not-yet-existing files and the
   /proc magic files where realpath refuses to resolve. */
static void resolve(const char *p, char *out, size_t n) {
    char *r;
    out[0] = 0;
    if (!p) return;
    r = realpath(p, NULL);
    if (r) {
        snprintf(out, n, "%s", r);
        free(r);
    }
}

/* The decision table (deny-list + caller gate) lives in a header so the host
   unit test exercises the SAME code we ship, not a copy that can drift.
   Getting this wrong once (a dead-code-eliminated deny path that still
   compiled and loaded cleanly) is why the test exists. */
#include "deny_logic.h"

FILE *fopen(const char *p, const char *m) {
    if (deny_for((unsigned long) __builtin_return_address(0), p)) {
        errno = EACCES;
        return NULL;
    }
    return _IO_fopen(p, m);
}

FILE *fopen64(const char *p, const char *m) {
    if (deny_for((unsigned long) __builtin_return_address(0), p)) {
        errno = EACCES;
        return NULL;
    }
    return _IO_fopen(p, m);
}

int open(const char *p, int f, ...) {
    mode_t mode = 0;
    if (f & O_CREAT) {
        va_list ap;
        va_start(ap, f);
        mode = (mode_t) va_arg(ap, int);
        va_end(ap);
    }
    if (deny_for((unsigned long) __builtin_return_address(0), p)) {
        errno = EACCES;
        return -1;
    }
    return openat(AT_FDCWD, p, f, mode);
}

int open64(const char *p, int f, ...) {
    mode_t mode = 0;
    if (f & O_CREAT) {
        va_list ap;
        va_start(ap, f);
        mode = (mode_t) va_arg(ap, int);
        va_end(ap);
    }
    if (deny_for((unsigned long) __builtin_return_address(0), p)) {
        errno = EACCES;
        return -1;
    }
    return openat(AT_FDCWD, p, f | O_LARGEFILE, mode);
}

/* CVE-2024-35341: the download handler shells out
   "cp /mnt/nand/config.xml /mnt/nand/ConfigFile.ini" and then serves the
   copy. Denying the fopen above is not enough -- the copy still happens.
   Gating this popen by its own call site stops the copy without touching any
   other shell escape the vendor uses (pidof, ps, df, cat /proc/mtd, ...). */
FILE *popen(const char *c, const char *m) {
    unsigned long ra = (unsigned long) __builtin_return_address(0);
    if (from_handler(ra, RA_CFGDL_POPEN) && c &&
        (strstr(c, "config.xml") || strstr(c, "ConfigFile.ini"))) {
        errno = EACCES;
        return NULL;
    }
    return _IO_popen(c, m);
}

int system(const char *c) {
    unsigned long ra = (unsigned long) __builtin_return_address(0);
    if (from_handler(ra, RA_CFGDL_POPEN) && c &&
        (strstr(c, "config.xml") || strstr(c, "ConfigFile.ini"))) {
        errno = EACCES;
        return -1;
    }
    return libc_system(c);
}
