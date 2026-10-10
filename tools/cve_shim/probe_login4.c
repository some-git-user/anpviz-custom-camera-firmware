/* probe_login4.c -- LOG-ONLY probe, step 4: can we detect a FAILED login?
 *
 * MsgUserGetPassword returns rc=0 for both good and bad passwords (it only
 * fetches the stored plaintext). The pass/fail compare happens in web_server
 * via a string compare. If that compare is strcmp/strncmp against the stored
 * password, we can detect it:
 *   - capture the stored password in the MsgUserGetPassword wrapper (TLS),
 *   - override strcmp/strncmp with our OWN correct implementations (no dlsym,
 *     no forwarding, no recursion) that ALSO log when one argument equals the
 *     stored password. The other argument is the supplied password; a nonzero
 *     return means the compare FAILED -> a failed login attempt.
 *
 * Overriding strcmp globally is only safe because our implementations are
 * byte-exact equivalents of the C standard ones. They are additionally gated:
 * the logging branch only runs when a thread-local stored password is set, so
 * the hot path is a plain compare.
 *
 * DENIES NOTHING. If the compare is NOT strcmp/strncmp (e.g. a custom
 * constant-time loop), this probe logs nothing and we learn the signal is
 * unavailable -> detection would have to count attempts, not failures.
 *
 * Build: $CC -O2 -fno-stack-protector -fPIC -shared -o probe_login4.so probe_login4.c
 */
#define _GNU_SOURCE
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <string.h>
#include <stddef.h>

#ifndef SYS_open
#define SYS_open 5
#endif
#ifndef SYS_read
#define SYS_read 3
#endif
#ifndef SYS_close
#define SYS_close 6
#endif
#ifndef SYS_write
#define SYS_write 4
#endif
#ifndef SYS_gettid
#define SYS_gettid 224
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

#define LOGPATH "/tmp/probe_login4.txt"
static int g_logfd = -2;

typedef int (*mugp_t)(const char *, char *);
static mugp_t g_real = 0;
static int g_tried = 0;
#define OFF 0x3f69cUL

/* Per-thread copy of the stored password captured at MsgUserGetPassword time.
   The compare happens on the same worker thread, so TLS is the right scope. */
static __thread char tls_stored[80];

static void log_init(void) {
    if (g_logfd != -2) return;
    g_logfd = (int)syscall(SYS_open, LOGPATH, O_WRONLY | O_CREAT | O_APPEND, 0666);
}
static int put_u(char *b, int cap, int *o, unsigned long v) {
    char t[12]; int n = 0;
    if (v == 0) t[n++] = '0'; else { while (v) { t[n++] = (char)('0'+(v%10)); v/=10; } }
    while (n > 0 && *o < cap) b[(*o)++] = t[--n]; return 0;
}
static int puts_(char *b, int cap, int *o, const char *s) {
    while (*s && *o < cap) b[(*o)++] = *s++; return 0;
}
static void log_cmp(const char *fn, const char *other, int result) {
    char buf[200]; int o = 0;
    if (g_logfd < 0) return;
    puts_(buf, sizeof buf, &o, fn);
    puts_(buf, sizeof buf, &o, " tid=");
    put_u(buf, sizeof buf, &o, (unsigned long)syscall(SYS_gettid));
    puts_(buf, sizeof buf, &o, " supplied=");
    puts_(buf, sizeof buf, &o, other ? other : "(null)");
    puts_(buf, sizeof buf, &o, " result=");
    put_u(buf, sizeof buf, &o, (unsigned long)(unsigned int)result);
    puts_(buf, sizeof buf, &o, (result==0 ? " MATCH\n" : " FAIL\n"));
    (void)syscall(SYS_write, g_logfd, buf, (size_t)o);
}

static unsigned long find_base(void) {
    char buf[8192]; int fd = (int)syscall(SYS_open, "/proc/self/maps", 0);
    if (fd < 0) return 0;
    int total = 0, n; char *p = buf;
    while ((n = (int)syscall(SYS_read, fd, p, (int)(sizeof buf - 1 - total))) > 0) {
        p += n; total += n; if (total >= (int)sizeof buf - 1) break;
    }
    (void)syscall(SYS_close, fd);
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
static mugp_t real_fn(void) {
    if (g_tried) return g_real;
    g_tried = 1;
    unsigned long base = find_base();
    if (base) {
        unsigned long addr = base + OFF;
        unsigned char *b = (unsigned char *)addr;
        if (b[0]==0x2f && b[1]==0x4b && b[2]==0x7b && b[3]==0x44)
            g_real = (mugp_t)(addr | 1UL);
    }
    return g_real;
}

int MsgUserGetPassword(const char *user, char *out) {
    log_init();
    mugp_t r = real_fn();
    int rc = -999;
    if (r) rc = r(user, out);
    /* Capture the stored plaintext for this thread so strcmp can spot the
       compare. out is a NUL-terminated plaintext password on success. */
    if (rc == 0 && out) {
        int i = 0;
        while (out[i] && i < (int)sizeof tls_stored - 1) { tls_stored[i] = out[i]; i++; }
        tls_stored[i] = 0;
    }
    return rc;
}

/* Canonical compare, never logs -- used internally so we never recurse. */
static int cmp_nolook(const char *a, const char *b) {
    const unsigned char *x = (const unsigned char *)a;
    const unsigned char *y = (const unsigned char *)b;
    while (*x && *x == *y) { x++; y++; }
    return (int)*x - (int)*y;
}

/* Our own strcmp: byte-exact standard semantics, plus detection. Overriding
   strcmp globally is safe ONLY because cmp_nolook is a correct equivalent;
   the logging branch is gated on a thread-local stored password so it is
   inert everywhere except the instant after a MsgUserGetPassword on this
   thread. */
int strcmp(const char *a, const char *b) {
    int res = cmp_nolook(a, b);
    if (tls_stored[0]) {
        if (a && cmp_nolook(a, tls_stored) == 0) log_cmp("STRCMP", b, res);
        else if (b && cmp_nolook(b, tls_stored) == 0) log_cmp("STRCMP", a, res);
    }
    return res;
}

/* Canonical bounded compare, never logs. */
static int cmpn_nolook(const char *a, const char *b, size_t n) {
    const unsigned char *x = (const unsigned char *)a;
    const unsigned char *y = (const unsigned char *)b;
    while (n) {
        if (*x != *y) return (int)*x - (int)*y;
        if (*x == 0) return 0;
        x++; y++; n--;
    }
    return 0;
}
int strncmp(const char *a, const char *b, size_t n) {
    int res = cmpn_nolook(a, b, n);
    if (tls_stored[0]) {
        if (a && cmp_nolook(a, tls_stored) == 0) log_cmp("STRNCMP", b, res);
        else if (b && cmp_nolook(b, tls_stored) == 0) log_cmp("STRNCMP", a, res);
    }
    return res;
}

/* Canonical memcmp, never logs. Byte-exact over n bytes. */
static int mem_nolook(const void *a, const void *b, size_t n) {
    const unsigned char *x = (const unsigned char *)a;
    const unsigned char *y = (const unsigned char *)b;
    for (size_t i = 0; i < n; i++) if (x[i] != y[i]) return (int)x[i] - (int)y[i];
    return 0;
}
static int is_stored_mem(const void *p, size_t n) {
    size_t sl = 0; while (tls_stored[sl]) sl++;
    if (sl != n) return 0;
    return mem_nolook((const char *)p, tls_stored, n) == 0;
}
int memcmp(const void *a, const void *b, size_t n) {
    int res = mem_nolook(a, b, n);
    if (tls_stored[0] && n > 0 && n < 80) {
        if (a && is_stored_mem(a, n)) log_cmp("MEMCMP", (const char *)b, res);
        else if (b && is_stored_mem(b, n)) log_cmp("MEMCMP", (const char *)a, res);
    }
    return res;
}
