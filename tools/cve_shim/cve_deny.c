/* ---------------------------------------------------------------------------
 * cve_deny.so -- LD_PRELOAD mitigation for the ANJVISION web_server CVEs.
 *
 * Closes, without vendor source:
 *   CVE-2024-35341  unauth GET /config.xml|/ConfigFile.ini  (popen "cp ...")
 *   CVE-2024-35343  unauth GET /playback/<path>  -> fopen() of ANY file
 *
 * Mechanism: interpose the libc calls the vulnerable handlers make through the
 * PLT (verified: web_server has R_ARM_JUMP_SLOT relocs for fopen, fopen64,
 * open, open64, popen, system).
 *
 * READ-ONLY DENY. The camera legitimately WRITES /mnt/nand/config.xml when you
 * save settings, so we only refuse READ-ONLY opens of sensitive paths. A mode
 * containing 'w', 'a' or '+' is passed through untouched.
 *
 * NO dlsym(): our toolchain's dlsym is GLIBC_2.34 (moved from libdl into libc)
 * and the device has glibc 2.19, so a dlsym-based shim fails to load with
 * "version GLIBC_2.34 not found". Instead we forward to glibc's own internal
 * aliases, which are plain GLIBC_2.4 on the device:
 *     fopen  -> _IO_fopen     popen -> _IO_popen
 * and open()/open64() -> openat(AT_FDCWD, ...), which we do not wrap.
 * ------------------------------------------------------------------------ */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>

/* glibc internal real implementations, GLIBC_2.4 on the target. */
extern FILE *_IO_fopen(const char *, const char *);
extern FILE *_IO_popen(const char *, const char *);

/* Files the web server never needs to READ for normal operation. Deliberately
   excludes /mnt/nand/config.xml: the vendor code reads that through ordinary
   fopen() for its own config ops, so denying it here would break the UI.
   The config-download CVE is a popen("cp ...") and is handled separately. */
static const char *const bad[] = {
    "/etc/passwd", "/etc/shadow", "/etc/group", "/etc/gshadow",
    "/dev/mtd", "/dev/block/mtd",
    "/proc/kcore", "/proc/self/mem", "/dev/mem",
    "/root/", "/etc/ssl/private", "/etc/ssh",
    NULL
};

/* Shell commands that implement the config-download / file-dump CVEs. */
static const char *const badcmd[] = {
    "config.xml", "ConfigFile.ini", "/etc/passwd", "/etc/shadow",
    "/dev/mtd", "/dev/mem", "/proc/kcore", NULL
};

static int sensitive(const char *p) {
    if (!p) return 0;
    for (int i = 0; bad[i]; i++)
        if (strstr(p, bad[i])) return 1;
    return 0;
}

/* read-only mode? "r" without 'w', 'a' or '+' */
static int readonly(const char *m) {
    if (!m) return 1;
    if (strchr(m, 'w') || strchr(m, 'a') || strchr(m, '+')) return 0;
    return 1;
}

FILE *fopen(const char *p, const char *m) {
    if (sensitive(p) && readonly(m)) { errno = EACCES; return NULL; }
    return _IO_fopen(p, m);
}
FILE *fopen64(const char *p, const char *m) {
    if (sensitive(p) && readonly(m)) { errno = EACCES; return NULL; }
    return _IO_fopen(p, m);
}

static int bad_command(const char *c) {
    if (!c) return 0;
    for (int i = 0; badcmd[i]; i++)
        if (strstr(c, badcmd[i])) return 1;
    return 0;
}

FILE *popen(const char *c, const char *m) {
    if (bad_command(c)) { errno = EACCES; return NULL; }
    return _IO_popen(c, m);
}

/* Only refuse reads; writes must keep working so config saves still function. */
static int writeish(int f) {
    return (f & (O_WRONLY | O_RDWR | O_CREAT | O_APPEND)) != 0;
}

/* open()/open64(): forward via openat so we do not recurse into ourselves. */
int open(const char *p, int f, ...) {
    if (sensitive(p) && !writeish(f)) { errno = EACCES; return -1; }
    mode_t mode = 0;
    if (f & O_CREAT) { va_list ap; va_start(ap, f);
        mode = (mode_t) va_arg(ap, int); va_end(ap); }
    return openat(AT_FDCWD, p, f, mode);
}
int open64(const char *p, int f, ...) {
    if (sensitive(p) && !writeish(f)) { errno = EACCES; return -1; }
    mode_t mode = 0;
    if (f & O_CREAT) { va_list ap; va_start(ap, f);
        mode = (mode_t) va_arg(ap, int); va_end(ap); }
    return openat(AT_FDCWD, p, f | O_LARGEFILE, mode);
}
