/* probe_login3.c -- LOG-ONLY probe, step 3.
 *
 * getuid authenticates via MsgUserGetPassword (GOT 0x2ffdb8), NOT MsgUserLogin.
 * This probe wraps accept(), getpeername() and MsgUserGetPassword() and logs
 * tid + args + return for each, so we can see:
 *   - whether the getuid worker calls getpeername() (-> client IP available
 *     at auth time, so a per-IP rate limit is possible), and
 *   - what MsgUserGetPassword returns on correct vs wrong password.
 *
 * Real MsgUserGetPassword resolved from /proc/self/maps (libtools base +
 * 0x3f69c). Safety: verify first bytes 2f 4b 7b 44 before calling.
 *
 * DENIES NOTHING.
 * Build: $CC -O2 -fno-stack-protector -fPIC -shared -o probe_login3.so probe_login3.c
 */
#define _GNU_SOURCE
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <string.h>
#include <stddef.h>

#ifndef SYS_accept
#define SYS_accept 285
#endif
#ifndef SYS_getpeername
#define SYS_getpeername 287
#endif
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

#define LOGPATH "/tmp/probe_login3.txt"
static int g_logfd = -2;

typedef int (*mugp_t)(const char *, char *);
static mugp_t g_real = 0;
static int g_tried = 0;
#define OFF 0x3f69cUL

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
static void logline(const char *tag, const char *u, int rc) {
    char buf[160]; int o = 0;
    if (g_logfd < 0) return;
    puts_(buf, sizeof buf, &o, tag);
    puts_(buf, sizeof buf, &o, " tid=");
    put_u(buf, sizeof buf, &o, (unsigned long)syscall(SYS_gettid));
    if (u) { puts_(buf, sizeof buf, &o, " user="); puts_(buf, sizeof buf, &o, u); }
    puts_(buf, sizeof buf, &o, " rc=");
    put_u(buf, sizeof buf, &o, (unsigned long)(unsigned int)rc);
    puts_(buf, sizeof buf, &o, "\n");
    (void)syscall(SYS_write, g_logfd, buf, (size_t)o);
}
static void log_ip(const char *tag, unsigned a, int rc) {
    char buf[160]; int o = 0;
    if (g_logfd < 0) return;
    puts_(buf, sizeof buf, &o, tag);
    puts_(buf, sizeof buf, &o, " tid=");
    put_u(buf, sizeof buf, &o, (unsigned long)syscall(SYS_gettid));
    puts_(buf, sizeof buf, &o, " ip=");
    put_u(buf, sizeof buf, &o, (a>>24)&0xff); puts_(buf, sizeof buf, &o, ".");
    put_u(buf, sizeof buf, &o, (a>>16)&0xff); puts_(buf, sizeof buf, &o, ".");
    put_u(buf, sizeof buf, &o, (a>>8)&0xff);  puts_(buf, sizeof buf, &o, ".");
    put_u(buf, sizeof buf, &o, a&0xff);
    puts_(buf, sizeof buf, &o, " rc=");
    put_u(buf, sizeof buf, &o, (unsigned long)(unsigned int)rc);
    puts_(buf, sizeof buf, &o, "\n");
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
            if (!memcmp(q, "libtools", 8)) {
                unsigned long s = 0; char *r = line;
                while (r < nl && *r != '-') {
                    unsigned c = *r;
                    unsigned v = (c>='0'&&c<='9')?(c-'0'):(((c|32)>='a'&&(c|32)<='f')?((c|32)-'a'+10):0);
                    s = s*16 + v; r++;
                }
                if (s) { (void)0; return s; }
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
            /* MsgUserGetPassword is THUMB code. Calling Thumb code through a
               function pointer requires the LSB (Thumb bit) set, else the CPU
               enters ARM mode and crashes. The PLT does this implicitly; our
               manual resolution must do it explicitly. */
            g_real = (mugp_t)(addr | 1UL);
    }
    return g_real;
}

int MsgUserGetPassword(const char *user, char *out) {
    log_init();
    mugp_t r = real_fn();
    int rc = -999;
    if (r) rc = r(user, out);
    logline("MUGP", user, rc);
    return rc;
}
int accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen) {
    log_init();
    int rc = (int)syscall(SYS_accept, sockfd, addr, addrlen);
    if (rc >= 0 && addr && addr->sa_family == AF_INET)
        log_ip("ACCEPT", ntohl(((struct sockaddr_in*)addr)->sin_addr.s_addr), rc);
    else
        logline("ACCEPT", 0, rc);
    return rc;
}
int getpeername(int fd, struct sockaddr *addr, socklen_t *addrlen) {
    log_init();
    int rc = (int)syscall(SYS_getpeername, fd, addr, addrlen);
    if (rc == 0 && addr && addr->sa_family == AF_INET)
        log_ip("GETPEERNAME", ntohl(((struct sockaddr_in*)addr)->sin_addr.s_addr), rc);
    else
        logline("GETPEERNAME", 0, rc);
    return rc;
}
