/* probe_login2.c -- LOG-ONLY probe, step 2.
 *
 * Answers the two remaining questions before we build a per-IP rate limiter
 * for the /cgi-bin/getuid credential oracle (CVE-2026-100298):
 *
 *   Q1 RETURN: what does MsgUserLogin() return on correct vs wrong password?
 *      We must know which value means "bad password" so the limiter counts
 *      failures, not successes.
 *   Q2 THREADING: is MsgUserLogin() called on the SAME thread that calls
 *      getpeername() (the request worker)? If yes, a thread-local peer IP set
 *      in getpeername() is readable at login time -> per-IP limit is possible.
 *
 * MsgUserLogin lives in libtools.so and is a PLT call from web_server, so we
 * interpose it by exporting the same symbol. We CANNOT use dlsym: the device
 * libc.so.6 has no dlsym (it is in libdl.so.2) and the toolchain mis-binds the
 * version reference to libc.so.6, so a dlsym shim dies at load. Instead we
 * resolve the REAL MsgUserLogin by parsing /proc/self/maps for libtools.so's
 * base and adding its known file offset (0x3f46c; first PT_LOAD maps file
 * offset 0 -> vaddr 0, so base + vaddr is the runtime address).
 *
 * This shim DENIES NOTHING. It forwards every MsgUserLogin to the real one and
 * logs tid + the four register args + the return value.
 *
 * Build:
 *   $CC -O2 -fno-stack-protector -fPIC -shared -o probe_login2.so probe_login2.c
 */
#define _GNU_SOURCE
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <string.h>
#include <stddef.h>

#ifndef SYS_getpeername
#define SYS_getpeername 287
#endif
#ifndef SYS_open
#define SYS_open 5
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

#define LOGPATH "/tmp/probe_login2.txt"
static int g_logfd = -2;

/* Real MsgUserLogin, resolved lazily from /proc/self/maps. */
typedef int (*mul_t)(const char *, const char *, const char *, char *);
static mul_t g_real_mul = 0;
static int g_mul_tried = 0;

/* File offset of MsgUserLogin in libtools.so (vaddr == file offset here). */
#define MSGUSERLOGIN_OFF 0x3f46cUL

static void log_init(void) {
    if (g_logfd != -2) return;
    g_logfd = (int)syscall(SYS_open, LOGPATH, O_WRONLY | O_CREAT | O_APPEND, 0666);
}

static int put_u(char *b, int cap, int *o, unsigned long v) {
    char t[12]; int n = 0;
    if (v == 0) t[n++] = '0';
    else { while (v) { t[n++] = (char)('0' + (v % 10)); v /= 10; } }
    while (n > 0 && *o < cap) b[(*o)++] = t[--n];
    return 0;
}
static int puts_(char *b, int cap, int *o, const char *s) {
    while (*s && *o < cap) b[(*o)++] = *s++;
    return 0;
}
static int put_hex(char *b, int cap, int *o, unsigned long v) {
    static const char hx[] = "0123456789abcdef";
    char t[16]; int n = 0;
    if (v == 0) t[n++] = '0';
    else { while (v) { t[n++] = hx[v & 0xf]; v >>= 4; } }
    while (n > 0 && *o < cap) b[(*o)++] = t[--n];
    return 0;
}

/* Read /proc/self/maps via raw syscalls (no stdio in a preload shim). Find the
   lowest mapping of libtools.so and return its base. */
static unsigned long find_libtools_base(void) {
    char buf[4096];
    int fd = (int)syscall(SYS_open, "/proc/self/maps", 0 /*O_RDONLY*/);
    if (fd < 0) return 0;
    unsigned long base = 0;
    int total = 0;
    /* Read once; maps for this process is small enough for one read for our
       purpose (libtools appears early). If not found, caller retries next call. */
    int n;
    char *p = buf;
    char *end = buf + sizeof buf;
    while ((n = (int)syscall(3 /*read*/, fd, p, (int)(end - p))) > 0) {
        p += n; total += n;
        if (p >= end) break;
    }
    (void)syscall(6 /*close*/, fd);
    buf[total < (int)sizeof buf ? total : (int)sizeof buf - 1] = 0;
    /* Scan lines for "libtools.so" with an r-xp mapping; first field is start. */
    char *line = buf;
    while (line && *line) {
        char *nl = line;
        while (*nl && *nl != '\n') nl++;
        /* does this line mention libtools.so? */
        if (nl - line > 12) {
            char *q = line;
            while (q < nl) {
                if (q[0]=='l'&&q[1]=='i'&&q[2]=='b'&&q[3]=='t'&&q[4]=='o'&&q[5]=='o'&&q[6]=='l'&&q[7]=='s') {
                    /* parse hex start at line */
                    unsigned long s = 0; char *r = line;
                    while (r < nl && *r != '-') {
                        unsigned c = *r;
                        unsigned v = (c>='0'&&c<='9')?(c-'0'):((c|32)>='a'&&(c|32)<='f')?((c|32)-'a'+10):0;
                        s = s*16 + v; r++;
                    }
                    if (s) { base = s; break; }
                }
                q++;
            }
        }
        if (base) break;
        line = (*nl == '\n') ? nl + 1 : nl;
    }
    return base;
}

static mul_t real_mul(void) {
    if (g_mul_tried) return g_real_mul;
    g_mul_tried = 1;
    unsigned long base = find_libtools_base();
    if (base) {
        unsigned long addr = base + MSGUSERLOGIN_OFF;
        /* Safety: MsgUserLogin's first Thumb instruction is
           e92d 4ff0 (stmdb sp!,{...}) -> little-endian bytes f0 4f 2d e9.
           If the resolved address does not start with it, our base/offset is
           wrong; refuse to call it rather than crash web_server. */
        unsigned char *b = (unsigned char *)addr;
        if (b[0]==0xf0 && b[1]==0x4f && b[2]==0x2d && b[3]==0xe9)
            g_real_mul = (mul_t)addr;
    }
    return g_real_mul;
}

static void log_mul(const char *u, const char *p, int rc, int resolved) {
    char buf[200]; int o = 0;
    if (g_logfd < 0) return;
    puts_(buf, sizeof buf, &o, "MSGUSERLOGIN tid=");
    put_u(buf, sizeof buf, &o, (unsigned long)syscall(SYS_gettid));
    puts_(buf, sizeof buf, &o, " user=");
    puts_(buf, sizeof buf, &o, u ? u : "(null)");
    puts_(buf, sizeof buf, &o, " pass=");
    puts_(buf, sizeof buf, &o, p ? p : "(null)");
    puts_(buf, sizeof buf, &o, " rc=");
    put_u(buf, sizeof buf, &o, (unsigned long)(unsigned int)rc);
    puts_(buf, sizeof buf, &o, " resolved=");
    put_u(buf, sizeof buf, &o, (unsigned long)resolved);
    puts_(buf, sizeof buf, &o, "\n");
    (void)syscall(SYS_write, g_logfd, buf, (size_t)o);
}

int MsgUserLogin(const char *user, const char *pass, const char *a3, char *a4) {
    log_init();
    mul_t r = real_mul();
    int rc = -999;
    if (r) rc = r(user, pass, a3, a4);
    log_mul(user, pass, rc, r ? 1 : 0);
    return rc;
}

int getpeername(int fd, struct sockaddr *addr, socklen_t *addrlen) {
    log_init();
    int rc = (int)syscall(SYS_getpeername, fd, addr, addrlen);
    if (rc == 0 && addr && addr->sa_family == AF_INET) {
        char buf[160]; int o = 0;
        unsigned a = ntohl(((struct sockaddr_in *)addr)->sin_addr.s_addr);
        puts_(buf, sizeof buf, &o, "GETPEERNAME tid=");
        put_u(buf, sizeof buf, &o, (unsigned long)syscall(SYS_gettid));
        puts_(buf, sizeof buf, &o, " ip=");
        put_u(buf, sizeof buf, &o, (a>>24)&0xff); puts_(buf, sizeof buf, &o, ".");
        put_u(buf, sizeof buf, &o, (a>>16)&0xff); puts_(buf, sizeof buf, &o, ".");
        put_u(buf, sizeof buf, &o, (a>>8)&0xff);  puts_(buf, sizeof buf, &o, ".");
        put_u(buf, sizeof buf, &o, a&0xff);
        puts_(buf, sizeof buf, &o, "\n");
        (void)syscall(SYS_write, g_logfd, buf, (size_t)o);
    }
    return rc;
}
