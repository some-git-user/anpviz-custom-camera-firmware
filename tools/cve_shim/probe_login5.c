/* probe_login5.c -- LOG-ONLY: can we correlate the client IP to the auth call?
 *
 * accept() gives (fd, ip). getpeername(fd) gives (ip) on a worker thread.
 * MsgUserGetPassword() is the auth call but carries no fd/ip.
 *
 * Test: stash the peer IP in __thread storage inside getpeername(), then read
 * it inside MsgUserGetPassword(). If MUGP reports a non-zero IP, the worker
 * that resolves the peer is the SAME thread that authenticates -> per-IP
 * logging is possible. Log tids too so the relationship is explicit.
 *
 * DENIES NOTHING.
 * Build: $CC -O2 -fno-stack-protector -fPIC -shared -o probe_login5.so probe_login5.c
 */
#define _GNU_SOURCE
#include <sys/socket.h>
#include <netinet/in.h>
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

#define LOGPATH "/tmp/probe_login5.txt"
static int g_logfd = -2;

typedef int (*mugp_t)(const char *, char *);
static mugp_t g_real = 0;
static int g_tried = 0;
#define OFF 0x3f69cUL

/* Thread-local peer IP, set by getpeername, read by MsgUserGetPassword. */
static __thread unsigned tls_ip = 0;

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
static void put_ip(char *b, int cap, int *o, unsigned a) {
    put_u(b, cap, o, (a>>24)&0xff); puts_(b, cap, o, ".");
    put_u(b, cap, o, (a>>16)&0xff); puts_(b, cap, o, ".");
    put_u(b, cap, o, (a>>8)&0xff);  puts_(b, cap, o, ".");
    put_u(b, cap, o, a&0xff);
}
static void log(const char *tag, const char *u, unsigned ip) {
    char buf[160]; int o = 0;
    if (g_logfd < 0) return;
    puts_(buf, sizeof buf, &o, tag);
    puts_(buf, sizeof buf, &o, " tid=");
    put_u(buf, sizeof buf, &o, (unsigned long)syscall(SYS_gettid));
    puts_(buf, sizeof buf, &o, " ip=");
    put_ip(buf, sizeof buf, &o, ip);
    if (u) { puts_(buf, sizeof buf, &o, " user="); puts_(buf, sizeof buf, &o, u); }
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
    /* Report the thread-local IP this worker currently holds. */
    log("MUGP", user, tls_ip);
    return rc;
}
int accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen) {
    log_init();
    int rc = (int)syscall(SYS_accept, sockfd, addr, addrlen);
    if (rc >= 0 && addr && addr->sa_family == AF_INET)
        log("ACCEPT", 0, ntohl(((struct sockaddr_in*)addr)->sin_addr.s_addr));
    else
        log("ACCEPT", 0, 0);
    return rc;
}
int getpeername(int fd, struct sockaddr *addr, socklen_t *addrlen) {
    log_init();
    int rc = (int)syscall(SYS_getpeername, fd, addr, addrlen);
    if (rc == 0 && addr && addr->sa_family == AF_INET) {
        unsigned ip = ntohl(((struct sockaddr_in*)addr)->sin_addr.s_addr);
        tls_ip = ip;                 /* stash for this thread */
        log("GETPEERNAME", 0, ip);
    } else {
        log("GETPEERNAME", 0, 0);
    }
    return rc;
}
