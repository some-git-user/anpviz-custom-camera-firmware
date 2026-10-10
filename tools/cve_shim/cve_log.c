/* ---------------------------------------------------------------------------
 * cve_log.so -- OBSERVATION ONLY. Denies nothing.
 *
 * Purpose: before we can write a deny-list that does not brick the camera we
 * need to know, empirically, which files the vendor stack opens and from where.
 * Specifically: does web_server read /mnt/nand/config.xml itself (in which
 * case we can NOT deny it), or does it get config through the SysV IPC
 * request/response path to mainctrl (in which case denying the file is safe)?
 *
 * Wraps the open family + shell escapes, logs raw path, realpath() resolution
 * and __builtin_return_address(0) so each hit can be mapped back to a
 * web_server offset with tools/xref2.py.
 *
 * NO dl*() ANYWHERE. The device's libc.so.6 exports no dlvsym/dlsym at all
 * (they live in libdl.so.2), while our glibc-2.39 sysroot has merged them
 * into libc and records the reference against libc.so.6. A dlvsym shim dies
 * at load on the target with:
 *   relocation error: symbol dlvsym, version GLIBC_2.4 not defined in file
 *   libc.so.6 with link time reference
 * Verified on .113. So every forward below is a direct symbol reference.
 *
 * NEVER ships. Diagnostic only.
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

/* Forward targets, each verified present in the device libc at the pinned
   version (arm-...-objdump -T builds/YM500L/rootfs/lib/libc-2.19-2014.04.so).
   _IO_fopen/_IO_popen are the REAL implementations, not thunks back into
   fopen/popen, so forwarding cannot recurse into ourselves. */
extern FILE *_IO_fopen(const char *, const char *);
extern FILE *_IO_popen(const char *, const char *);
extern int openat(int, const char *, int, ...);
extern char *realpath(const char *, char *);

/* The public `system` is a weak alias of a GLIBC_PRIVATE symbol. Binding the
   private name lets us interpose `system` without dlvsym. Verified loadable
   on .113 (LD_PRELOAD of a minimal probe using exactly this returned LOAD_OK). */
__asm__(".symver libc_system,__libc_system@GLIBC_PRIVATE");
extern int libc_system(const char *);

#define LOGPATH "/tmp/cve_log.txt"

static int logfd = -1;

static void log_init(void) {
    if (logfd >= 0) return;
    logfd = openat(AT_FDCWD, LOGPATH, O_WRONLY | O_CREAT | O_APPEND, 0644);
}

/* Minimal formatter: we avoid stdio in the logger to keep it out of the
   fopen path we are instrumenting.
   The PID is part of every line. Without it the log cannot be attributed:
   procman's ten children all append here, and telling web_server apart from
   mainctrl is the entire point of the exercise. getpid() is called per line
   rather than cached because popen() forks -- a cached PID would report the
   parent for work done in the child. */
static void log_line(const char *tag, const char *a, const char *b, void *ra) {
    char buf[1024];
    int n;
    log_init();
    if (logfd < 0) return;
    n = snprintf(buf, sizeof buf, "%d|%s|%s|%s|ra=%p\n", (int) getpid(), tag,
                 a ? a : "(null)", b ? b : "-", ra);
    if (n > 0) {
        if (n > (int) sizeof buf) n = sizeof buf;
        ssize_t w = write(logfd, buf, (size_t) n);
        (void) w;
    }
}

static void resolve(const char *p, char *out, size_t n) {
    out[0] = 0;
    if (!p) return;
    char *r = realpath(p, NULL);   /* GLIBC_2.4 on the target */
    if (r) {
        snprintf(out, n, "%s", r);
        free(r);
    } else {
        snprintf(out, n, "(unresolved)");
    }
}

FILE *fopen(const char *p, const char *m) {
    char r[PATH_MAX];
    resolve(p, r, sizeof r);
    log_line("fopen", p, r, __builtin_return_address(0));
    return _IO_fopen(p, m);
}

FILE *fopen64(const char *p, const char *m) {
    char r[PATH_MAX];
    resolve(p, r, sizeof r);
    log_line("fopen64", p, r, __builtin_return_address(0));
    return _IO_fopen(p, m);
}

int open(const char *p, int f, ...) {
    char r[PATH_MAX];
    mode_t mode = 0;
    if (f & O_CREAT) { va_list ap; va_start(ap, f); mode = (mode_t) va_arg(ap, int); va_end(ap); }
    resolve(p, r, sizeof r);
    log_line("open", p, r, __builtin_return_address(0));
    return openat(AT_FDCWD, p, f, mode);
}

int open64(const char *p, int f, ...) {
    char r[PATH_MAX];
    mode_t mode = 0;
    if (f & O_CREAT) { va_list ap; va_start(ap, f); mode = (mode_t) va_arg(ap, int); va_end(ap); }
    resolve(p, r, sizeof r);
    log_line("open64", p, r, __builtin_return_address(0));
    return openat(AT_FDCWD, p, f | O_LARGEFILE, mode);
}

FILE *popen(const char *c, const char *m) {
    log_line("popen", c, "-", __builtin_return_address(0));
    return _IO_popen(c, m);
}

int system(const char *c) {
    log_line("system", c, "-", __builtin_return_address(0));
    return libc_system(c);
}
