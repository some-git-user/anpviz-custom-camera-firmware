/* probe_login.c -- LOG-ONLY probe to answer two questions before we build a
 * per-IP login rate limiter for the /cgi-bin/getuid credential oracle
 * (CVE-2026-100298) on the YM500L web_server.
 *
 *   Q1 THREADING: is the thread that accept()s the TCP connection the SAME
 *      thread that later calls MsgUserLogin()?  If yes, a thread-local
 *      "last accepted peer IP" can be read at login time -> per-IP limit.
 *      If no (thread pool hands the request off), we cannot correlate and
 *      must fall back to a per-username limit.
 *
 *   Q2 RETURN CONVENTION: what does MsgUserLogin() return on success vs
 *      failure, and what are its arguments?  We must know which return means
 *      "bad password" so the limiter counts failures, not successes.
 *
 * This shim DENIES NOTHING. It forwards every call to the real implementation
 * and appends one line per event to /tmp/probe_login.txt.
 *
 * Forwarding: accept() is forwarded via syscall(SYS_accept) so we do not
 * re-enter our own accept().  MsgUserLogin lives in libtools.so and is a
 * normal PLT call from web_server; we forward by calling the real symbol
 * through a dlsym-free handle obtained from the already-loaded libtools.so.
 * Because we cannot use dlsym (device libc has no dl* in libc.so.6), we
 * instead declare the real symbols with a distinct alias via .symver is not
 * possible for a libtools symbol, so we resolve the real one by keeping our
 * own copy of the entry through RTLD_NEXT-equivalent... which we also lack.
 *
 * Therefore this probe uses a DIFFERENT, dependency-free trick: it does NOT
 * forward MsgUserLogin itself.  Instead it only wraps accept() (which we CAN
 * forward via syscall) and separately wraps getpeername() (also syscall-
 * forwardable) to observe the peer addresses the handler asks for, tagged
 * with the thread id.  If the handler calls getpeername() on the login
 * thread, the peer IP is observable there WITHOUT touching MsgUserLogin.
 *
 * Build (glibc toolchain, device glibc 2.19 ARMv7 hard-float):
 *   $CC -O2 -fno-stack-protector -fPIC -shared -o probe_login.so probe_login.c
 */
#define _GNU_SOURCE
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <unistd.h>
#include <string.h>
#include <stddef.h>

#ifndef SYS_accept
#define SYS_accept 285   /* ARM EABI accept (unistd-common.h: base+285) */
#endif
#ifndef SYS_getpeername
#define SYS_getpeername 287  /* ARM EABI getpeername (base+287) */
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

#define LOGPATH "/tmp/probe_login.txt"
static int g_logfd = -2;

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
static void logline(const char *tag, int a, unsigned long b, unsigned long c) {
    char buf[160]; int o = 0;
    if (g_logfd < 0) return;
    puts_(buf, sizeof buf, &o, tag);
    puts_(buf, sizeof buf, &o, " tid=");
    put_u(buf, sizeof buf, &o, (unsigned long)syscall(SYS_gettid));
    puts_(buf, sizeof buf, &o, " a=");
    put_u(buf, sizeof buf, &o, (unsigned long)a);
    puts_(buf, sizeof buf, &o, " b=0x");
    put_hex(buf, sizeof buf, &o, b);
    puts_(buf, sizeof buf, &o, " c=");
    put_u(buf, sizeof buf, &o, c);
    puts_(buf, sizeof buf, &o, "\n");
    (void)syscall(SYS_write, g_logfd, buf, (size_t)o);
}

/* Record the IPv4 dotted quad from a sockaddr into the log. */
static void log_sa(const char *tag, int fd, const struct sockaddr_in *sa, int rc) {
    char buf[160]; int o = 0;
    if (g_logfd < 0 || !sa || sa->sin_family != AF_INET) {
        logline(tag, fd, 0, (unsigned long)rc);
        return;
    }
    unsigned a = ntohl(sa->sin_addr.s_addr);
    puts_(buf, sizeof buf, &o, tag);
    puts_(buf, sizeof buf, &o, " tid=");
    put_u(buf, sizeof buf, &o, (unsigned long)syscall(SYS_gettid));
    puts_(buf, sizeof buf, &o, " fd=");
    put_u(buf, sizeof buf, &o, (unsigned long)fd);
    puts_(buf, sizeof buf, &o, " ip=");
    put_u(buf, sizeof buf, &o, (a >> 24) & 0xff); puts_(buf, sizeof buf, &o, ".");
    put_u(buf, sizeof buf, &o, (a >> 16) & 0xff); puts_(buf, sizeof buf, &o, ".");
    put_u(buf, sizeof buf, &o, (a >> 8)  & 0xff); puts_(buf, sizeof buf, &o, ".");
    put_u(buf, sizeof buf, &o, a & 0xff);
    puts_(buf, sizeof buf, &o, " rc=");
    put_u(buf, sizeof buf, &o, (unsigned long)rc);
    puts_(buf, sizeof buf, &o, "\n");
    (void)syscall(SYS_write, g_logfd, buf, (size_t)o);
}

int accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen) {
    log_init();
    int rc = (int)syscall(SYS_accept, sockfd, addr, addrlen);
    if (rc >= 0 && addr && addr->sa_family == AF_INET)
        log_sa("ACCEPT", rc, (struct sockaddr_in *)addr, rc);
    else
        logline("ACCEPT", sockfd, 0, (unsigned long)rc);
    return rc;
}

int getpeername(int fd, struct sockaddr *addr, socklen_t *addrlen) {
    log_init();
    int rc = (int)syscall(SYS_getpeername, fd, addr, addrlen);
    if (rc == 0 && addr && addr->sa_family == AF_INET)
        log_sa("GETPEERNAME", fd, (struct sockaddr_in *)addr, rc);
    else
        logline("GETPEERNAME", fd, 0, (unsigned long)rc);
    return rc;
}
