/* egress_log.c -- LOG-ONLY interposer for outbound connect().
 *
 * Purpose: learn the camera's REAL outbound (egress) set before we write any
 * deny policy for the SSRF in /cgi-bin/connect_check. A wrong deny here
 * breaks P2P remote view / NTP / DDNS and costs a reflash, so we measure
 * first. This file DENIES NOTHING -- it forwards every connect and records
 * the destination so we can see what is load-bearing.
 *
 * Why connect() and not recv(): the SSRF is reachable over HTTPS, and TLS is
 * terminated INSIDE web_server (static OpenSSL, no interposable mbedtls), so
 * recv() only ever sees ciphertext. connect() sees the resolved destination
 * regardless of TLS, so it is the correct chokepoint -- and it needs no
 * hard-coded handler offsets, so it survives any firmware rebuild.
 *
 * Forwarding is via syscall(SYS_connect) so we never re-enter our own
 * connect() (no recursion). The syscall symbol (GLIBC_2.4) is confirmed
 * present on the device libc (0x90830).
 *
 * Build (glibc toolchain, device is glibc 2.19 ARMv7 hard-float):
 *   $CC -O2 -fno-stack-protector -fPIC -shared -o egress_log.so egress_log.c
 */
#define _GNU_SOURCE
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <string.h>
#include <stddef.h>

#ifndef SYS_connect
#define SYS_connect 42   /* ARM OABI/EABI connect */
#endif
#ifndef SYS_open
#define SYS_open 5
#endif
#ifndef SYS_write
#define SYS_write 4
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

#define LOGPATH "/tmp/egress_log.txt"

static int g_logfd = -2;   /* -2 = not yet opened, -1 = open failed */

static void log_init(void) {
    if (g_logfd != -2) return;
    g_logfd = (int)syscall(SYS_open, LOGPATH, O_WRONLY | O_CREAT | O_APPEND, 0666);
}

/* Minimal integer writers -- avoid pulling printf machinery into a shim that
   runs in every process. */
static int put_u(char *b, int cap, int *o, unsigned long v) {
    char t[12];
    int n = 0;
    if (v == 0) { t[n++] = '0'; }
    else { while (v) { t[n++] = (char)('0' + (v % 10)); v /= 10; } }
    while (n > 0 && *o < cap) b[(*o)++] = t[--n];
    return 0;
}
static int put_hex(char *b, int cap, int *o, unsigned long v) {
    static const char hx[] = "0123456789abcdef";
    char t[16];
    int n = 0;
    if (v == 0) { t[n++] = '0'; }
    else { while (v) { t[n++] = hx[v & 0xf]; v >>= 4; } }
    while (n > 0 && *o < cap) b[(*o)++] = t[--n];
    return 0;
}
static void puts_(const char *s, char *b, int cap, int *o) {
    while (*s && *o < cap) b[(*o)++] = *s++;
}

static void emit(const char *kind, const char *dst, unsigned long ra) {
    char b[160];
    int o = 0;
    puts_(kind, b, sizeof b, &o);
    b[o++] = '|';
    puts_(dst, b, sizeof b, &o);
    puts_("|ra=0x", b, sizeof b, &o);
    put_hex(b, sizeof b, &o, ra);
    b[o++] = '\n';
    if (g_logfd >= 0) {
        ssize_t r = syscall(SYS_write, g_logfd, b, (size_t)o);
        (void)r;
    }
}

/* Classify a sockaddr into a printable destination string. */
static void fmt_dst(const struct sockaddr *a, socklen_t len, char *out, int cap) {
    if (!a || len == 0) { strncpy(out, "(null)", cap); return; }
    if (a->sa_family == AF_INET) {
        const struct sockaddr_in *s = (const struct sockaddr_in *)(const void *)a;
        const unsigned char *p = (const unsigned char *)&s->sin_addr.s_addr;
        int o = 0;
        put_u(out, cap, &o, p[0]); out[o++]='.';
        put_u(out, cap, &o, p[1]); out[o++]='.';
        put_u(out, cap, &o, p[2]); out[o++]='.';
        put_u(out, cap, &o, p[3]); out[o++]=':';
        put_u(out, cap, &o, ntohs(s->sin_port));
        out[o] = 0;
        return;
    }
    if (a->sa_family == AF_INET6) {
        const struct sockaddr_in6 *s = (const struct sockaddr_in6 *)(const void *)a;
        const unsigned short *w = (const unsigned short *)s->sin6_addr.s6_addr;
        int o = 0;
        puts_("[", out, cap, &o);
        for (int i = 0; i < 8; i++) {
            put_hex(out, cap, &o, ntohs(w[i]));
            if (i < 7) out[o++] = ':';
        }
        out[o++] = ']'; out[o++] = ':';
        put_u(out, cap, &o, ntohs(s->sin6_port));
        out[o] = 0;
        return;
    }
    if (a->sa_family == AF_UNIX) { strncpy(out, "AF_UNIX(local)", cap); return; }
    strncpy(out, "AF_other", cap);
}

int connect(int fd, const struct sockaddr *a, socklen_t len) {
    log_init();
    char dst[96];
    fmt_dst(a, len, dst, sizeof dst);
    unsigned long ra = (unsigned long)__builtin_return_address(0);
    emit("connect", dst, ra);
    /* LOG ONLY: forward unconditionally via the raw syscall. */
    return (int)syscall(SYS_connect, fd, a, len);
}

/* connect_check returns alive/dead WITHOUT calling connect() and without the
   ping binary. Hypothesis: raw ICMP socket + sendto(). Wrap socket() and
   sendto() to confirm the family/type/protocol actually used, so we know
   what to gate. LOG ONLY -- forwards everything.
   NOTE: do NOT hand-pick syscall numbers. <sys/syscall.h> provides the
   correct ARM-EABI values (socket=281, sendto=290, connect=283); an
   earlier draft's fallback of 370 for sendto was simply wrong, so the
   fallbacks are removed rather than trusted. */

int socket(int domain, int type, int protocol) {
    log_init();
    char b[96]; int o = 0;
    puts_("socket|dom=", b, sizeof b, &o);
    put_u(b, sizeof b, &o, (unsigned)domain);
    puts_("|type=", b, sizeof b, &o);
    put_u(b, sizeof b, &o, (unsigned)type);
    puts_("|proto=", b, sizeof b, &o);
    put_u(b, sizeof b, &o, (unsigned)protocol);
    puts_("|ra=0x", b, sizeof b, &o);
    put_hex(b, sizeof b, &o, (unsigned long)__builtin_return_address(0));
    b[o++] = '\n';
    if (g_logfd >= 0) { ssize_t r = syscall(SYS_write, g_logfd, b, (size_t)o); (void)r; }
    return (int)syscall(SYS_socket, domain, type, protocol);
}

int sendto(int fd, const void *msg, size_t len, int flags,
           const struct sockaddr *a, socklen_t alen) {
    log_init();
    char dst[96];
    fmt_dst(a, alen, dst, sizeof dst);
    char b[160]; int o = 0;
    puts_("sendto|", b, sizeof b, &o);
    puts_(dst, b, sizeof b, &o);
    puts_("|ra=0x", b, sizeof b, &o);
    put_hex(b, sizeof b, &o, (unsigned long)__builtin_return_address(0));
    b[o++] = '\n';
    if (g_logfd >= 0) { ssize_t r = syscall(SYS_write, g_logfd, b, (size_t)o); (void)r; }
    return (int)syscall(SYS_sendto, fd, msg, len, flags, a, alen);
}
