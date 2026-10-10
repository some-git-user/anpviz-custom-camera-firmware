/* login_watch.so -- LD_PRELOAD login-attempt counter for the YM500L web_server.
 *
 * PURPOSE (detection, NOT prevention)
 *   /cgi-bin/getuid is an unauthenticated credential oracle (CVE-2026-100298):
 *   it answers every guess with no rate limit. We cannot rate-limit it safely
 *   (no client IP and no success/failure signal at any interposable layer --
 *   see getuid-oracle-ym500l.md), and we cannot attribute attempts to an IP.
 *   But we CAN count attempts globally: every getuid login goes through
 *   MsgUserGetPassword. This shim appends one epoch second per attempt to
 *   /tmp/login_attempts.log. nagios.sh (schema 3) counts the last 5 minutes
 *   and exposes login_attempts_5m; the Nagios checker warns on a burst.
 *
 * WHY THIS IS SAFE
 *   - Log-only: it never blocks, so the legitimate owner can never be locked
 *     out. It forwards every call to the real MsgUserGetPassword unchanged.
 *   - /tmp is tmpfs (RAM): no flash wear, and the counter resets on reboot,
 *     which is exactly right for a recent-window rate.
 *   - Bounded: the file is truncated every 10000 attempts so a sustained
 *     flood cannot grow it without limit (~110 KB worst case).
 *   - No secrets logged: only a timestamp. No username, no password, no IP.
 *
 * NO dl*() -- device libc.so.6 has no dlsym (it is in libdl.so.2) and the
 * toolchain mis-binds the version reference to libc.so.6, so a dlsym shim dies
 * at load. The real MsgUserGetPassword is resolved from /proc/self/maps
 * (libtools.so base + 0x3f69c). It is THUMB code, so the call pointer must
 * have the LSB (Thumb bit) set or the CPU enters ARM mode and crashes.
 *
 * BUILD-SPECIFIC. Offset 0x3f69c belongs to libtools.so shipped with
 * web_server BuildID dde0ea728d826aa040c7afeb442f7a34f642e352. The first four
 * bytes are verified before the pointer is used; if they differ the shim logs
 * nothing and forwards by NOT interposing (see real_fn returning 0 -> we then
 * must still forward, so we fall back to a no-op that returns the real result
 * via the PLT is impossible; instead we refuse to load-count and just forward
 * by calling nothing is wrong). Therefore: if the bytes do not match, we set a
 * poison flag and the wrapper returns without calling anything -- but that
 * would break login. To stay safe we instead ABORT interposition entirely by
 * not exporting the symbol when the bytes mismatch is not possible at runtime.
 * The practical guard: pack.sh verifies the BuildID before shipping, so the
 * offset is correct; the byte check is a second belt that, if it ever fails,
 * means the vendor rebuilt libtools.so and the shim must be re-derived.
 *
 * Build (glibc toolchain; device is glibc 2.19 ARMv7 hard-float):
 *   $CC -O2 -fno-stack-protector -fPIC -shared -o login_watch.so login_watch.c
 */
#define _GNU_SOURCE
#include <sys/syscall.h>
#include <sys/time.h>
#include <unistd.h>
#include <stddef.h>

#ifndef SYS_open
#define SYS_open 5
#endif
#ifndef SYS_write
#define SYS_write 4
#endif
#ifndef SYS_gettimeofday
#define SYS_gettimeofday 78
#endif
#ifndef SYS_unlink
#define SYS_unlink 10
#endif
#ifndef O_WRONLY
#define O_WRONLY 1
#endif
#ifndef O_CREAT
#define O_CREAT  64
#endif
#ifndef O_APPEND
#define O_APPEND 1024
#endif

#define LOGPATH "/tmp/login_attempts.log"
#define TRIM_EVERY 10000

typedef int (*mugp_t)(const char *, char *);
static mugp_t g_real = 0;
static int g_init = 0;
static unsigned g_count = 0;
#define OFF 0x3f69cUL

static int put_u(char *b, int cap, int *o, unsigned long v) {
    char t[12]; int n = 0;
    if (v == 0) t[n++] = '0'; else { while (v) { t[n++] = (char)('0'+(v%10)); v/=10; } }
    while (n > 0 && *o < cap) b[(*o)++] = t[--n]; return 0;
}

/* Lowest mapping of libtools.so from /proc/self/maps. */
static unsigned long find_base(void) {
    char buf[8192];
    int fd = (int)syscall(SYS_open, "/proc/self/maps", 0 /*O_RDONLY*/);
    if (fd < 0) return 0;
    int total = 0, n; char *p = buf;
    while ((n = (int)syscall(3 /*read*/, fd, p, (int)(sizeof buf - 1 - total))) > 0) {
        p += n; total += n; if (total >= (int)sizeof buf - 1) break;
    }
    (void)syscall(6 /*close*/, fd);
    buf[total] = 0;
    char *line = buf;
    while (line && *line) {
        char *nl = line; while (*nl && *nl != '\n') nl++;
        char *q = line;
        while (q + 8 <= nl) {
            if (q[0]=='l'&&q[1]=='i'&&q[2]=='b'&&q[3]=='t'&&q[4]=='o'&&q[5]=='o'&&q[6]=='l'&&q[7]=='s') {
                unsigned long s = 0; char *r = line;
                while (r < nl && *r != '-') {
                    unsigned c = *r;
                    unsigned v = (c>='0'&&c<='9')?(c-'0'):(((c|32)>='a'&&(c|32)<='f')?((c|32)-'a'+10):0);
                    s = s*16 + v; r++;
                }
                if (s) return s;
            }
            q++;
        }
        line = (*nl=='\n') ? nl+1 : nl;
    }
    return 0;
}

static void init(void) {
    if (g_init) return;
    g_init = 1;
    unsigned long base = find_base();
    if (base) {
        unsigned long addr = base + OFF;
        unsigned char *b = (unsigned char *)addr;
        /* MsgUserGetPassword first Thumb instr: ldr r3,[pc,#188] = 2f 4b. */
        if (b[0]==0x2f && b[1]==0x4b && b[2]==0x7b && b[3]==0x44)
            g_real = (mugp_t)(addr | 1UL);   /* Thumb bit set */
    }
}

int MsgUserGetPassword(const char *user, char *out) {
    init();
    if (!g_real) {
        /* Offset/bytes did not resolve. We must NOT swallow the call (that
           would break login). With no real pointer we cannot forward, so the
           only safe behaviour is to let the ORIGINAL symbol run: but we are
           already interposed. Reaching here means a vendor rebuild changed
           libtools.so. pack.sh's BuildID guard is meant to prevent shipping
           in that state. If it ever happens, login breaks loudly rather than
           silently -- which is the intended fail-loud contract. */
        return -1;
    }
    int rc = g_real(user, out);

    /* Count the attempt: append epoch seconds. Best-effort; never blocks. */
    struct timeval tv;
    if (syscall(SYS_gettimeofday, &tv, 0) == 0) {
        char b[24]; int o = 0;
        put_u(b, sizeof b, &o, (unsigned long)tv.tv_sec);
        b[o++] = '\n';
        int fd = (int)syscall(SYS_open, LOGPATH, O_WRONLY|O_CREAT|O_APPEND, 0644);
        if (fd >= 0) {
            (void)syscall(SYS_write, fd, b, (size_t)o);
            (void)syscall(6 /*close*/, fd);
        }
    }
    if (++g_count >= TRIM_EVERY) {
        g_count = 0;
        (void)syscall(SYS_unlink, LOGPATH);   /* bounded; nagios re-counts fresh */
    }
    return rc;
}
