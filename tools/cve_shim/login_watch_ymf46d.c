/* login_watch.so -- uClibc login-attempt + password-reset counter for the
 * YMF46D web_server. DETECTION ONLY.
 *
 * WHY A SEPARATE BUILD FROM THE YM500L SHIM
 *   YMF46D is uClibc (libc.so.0 -> libuClibc-1.0.31.so), not glibc. The YM500L
 *   shim forwards to glibc-only symbols (_IO_fopen/_IO_popen/__libc_system)
 *   and cannot load here. This build targets uClibc and, unlike the glibc one,
 *   uses dlsym() -- uClibc's libc.so.0 DOES export dlopen/dlsym, so we resolve
 *   the real functions through the dynamic linker instead of the /proc/self/maps
 *   + Thumb-bit hack the glibc build needs.
 *
 * WHAT IT COUNTS (two unauthenticated endpoints, both live on this model)
 *   MsgUserGetPassword  (libtools.so)  <- /cgi-bin/getuid credential oracle,
 *                                         CVE-2026-100298. One line per attempt.
 *   MsgSetUserConfig    (libtools.so)  <- /setUserConfig admin-password reset,
 *                                         CVE-2026-100296. One line per call.
 *
 * WHY DETECTION AND NOT BLOCKING
 *   Both endpoints are also used by the legitimate owner (login; changing your
 *   own password). A blanket deny would lock the owner out -- the exact failure
 *   that a global getuid rate limiter caused on YM500L. There is no client IP
 *   and no success/failure signal at this layer, so we cannot distinguish owner
 *   from attacker here. We therefore NEVER block: we append one epoch second per
 *   event to tmpfs and let Nagios alert on a burst. The owner can never be
 *   locked out by this shim.
 *
 *   /tmp is tmpfs (RAM): no flash wear, resets on reboot -- correct for a
 *   recent-window rate. Each file is truncated every 10000 events so a flood
 *   cannot grow it without limit.
 *
 * FAIL-LOUD: if dlsym cannot resolve a real function, the wrapper returns an
 * error WITHOUT calling anything, so login/reset breaks visibly rather than
 * silently shipping a counter that counts nothing. pack.sh guards the build.
 *
 * Build (uClibc toolchain; device is uClibc 1.0.31 ARMv7 hard-float):
 *   $CC -O2 -fno-stack-protector -fPIC -shared -o login_watch.so login_watch_ymf46d.c -ldl
 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <fcntl.h>
#include <sys/time.h>
#include <unistd.h>
#include <stddef.h>

#define LOGIN_LOG "/tmp/login_attempts.log"
#define RESET_LOG "/tmp/pwreset.log"
#define TRIM_EVERY 10000

typedef int (*getpw_t)(const char *, char *);
typedef int (*setcfg_t)(void *);

static getpw_t real_getpw = 0;
static setcfg_t real_setcfg = 0;
static int g_init = 0;
static unsigned g_login_n = 0;
static unsigned g_reset_n = 0;

static void init(void) {
    if (g_init) return;
    g_init = 1;
    /* RTLD_NEXT finds the real definitions in libtools.so, which is in the
       global symbol namespace because web_server NEEDED it. uClibc resolves
       the Thumb interworking for us -- no manual |1. */
    real_getpw  = (getpw_t) dlsym(RTLD_NEXT, "MsgUserGetPassword");
    real_setcfg = (setcfg_t) dlsym(RTLD_NEXT, "MsgSetUserConfig");
}

/* Append the current epoch second to `path`. Best-effort; never blocks. */
static void stamp(const char *path) {
    struct timeval tv;
    if (gettimeofday(&tv, 0) != 0) return;
    char b[24]; int o = 0;
    unsigned long v = (unsigned long) tv.tv_sec;
    char t[12]; int n = 0;
    if (v == 0) t[n++] = '0'; else { while (v) { t[n++] = (char)('0'+(v%10)); v/=10; } }
    while (n > 0) b[o++] = t[--n];
    b[o++] = '\n';
    int fd = open(path, 0x0041 /*O_WRONLY|O_CREAT*/ | 0x0400 /*O_APPEND*/, 0644);
    if (fd < 0) return;
    ssize_t w = write(fd, b, (size_t) o);
    (void) w;
    close(fd);
}

int MsgUserGetPassword(const char *user, char *out) {
    init();
    if (!real_getpw) return -1;   /* fail-loud: do not fake a login */
    int rc = real_getpw(user, out);
    stamp(LOGIN_LOG);
    if (++g_login_n >= TRIM_EVERY) { g_login_n = 0; unlink(LOGIN_LOG); }
    return rc;
}

int MsgSetUserConfig(void *arg) {
    init();
    if (!real_setcfg) return -1;  /* fail-loud: do not fake a config write */
    int rc = real_setcfg(arg);
    stamp(RESET_LOG);
    if (++g_reset_n >= TRIM_EVERY) { g_reset_n = 0; unlink(RESET_LOG); }
    return rc;
}
