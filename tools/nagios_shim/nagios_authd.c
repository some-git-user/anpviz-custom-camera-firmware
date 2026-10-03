/* nagios_authd.c -- LD_PRELOAD shim adding an authenticated /cgi-bin/nagios route.
 *
 * Interposes the vendor CGI dispatcher (libcgibin_curl.so) to expose a Nagios
 * monitoring feed that reuses the device's existing "manage user" web UI for
 * credentials. No vendor crypto is reimplemented: the stored plaintext is read
 * back through the vendor's own MsgUserGetPassword().
 *
 * Verified ABI (see repo memory anjoy-cgi-shim.md):
 *   http_cgi_bin() gates on http_cgi_find(uri,...) then calls
 *   http_cgi_handle(const char *uri, char *out, const char *client_ip)
 *     uri       = full request target incl. query, e.g. /cgi-bin/nagios?...
 *     out       = caller-allocated 102400-byte buffer (handler sprintf's body here)
 *     client_ip = peer address string
 *   returns HTTP status; caller sends `out` as the body with that status.
 *
 * Auth model (query-string, reuses vendor user DB):
 *   GET /cgi-bin/nagios?nagios_user=<u>&nagios_pass=<p>
 *   - <u> must name an account created in the web "manage user" UI.
 *   - MsgUserGetPassword(<u>, stored) returns the stored plaintext.
 *   - constant-time compare <p> against stored.
 *   Distinct param names avoid the vendor cgi_get_value "username" substring
 *   collisions that make cgi_is_valid_username_password order-sensitive.
 *
 * FAIL CLOSED: if the auth helpers cannot be resolved, auth fails, or the feed
 * is unreadable/empty, we return an error and never leak data.
 *
 * Audit: one line per nagios request to /tmp/nagios_auth.log (no credential).
 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

#define NAGIOS_PREFIX "/cgi-bin/nagios"
#define FEED_PATH     "/tmp/nagios.txt"
#define AUDIT_PATH    "/tmp/nagios_auth.log"
#define FEED_MAX      8192   /* our feed is ~500 B; cap defensively */
#define USER_KEY      "nagios_user"
#define PASS_KEY      "nagios_pass"

typedef int (*handle_fn)(const char *uri, char *out, const char *client_ip);
typedef int (*find_fn)(const char *uri, const void *r1, long table_off);
typedef int (*getval_fn)(const char *hay, const char *key, char *out, int max);
typedef int (*getpw_fn)(const char *uid, char *out);

static handle_fn real_handle;
static find_fn real_find;

static int is_nagios(const char *uri)
{
    return uri && strncmp(uri, NAGIOS_PREFIX, sizeof(NAGIOS_PREFIX) - 1) == 0;
}

/* Claim /cgi-bin/nagios so http_cgi_bin proceeds to the dispatcher.
 * Everything else is forwarded unchanged. */
int http_cgi_find(const char *uri, const void *r1, long table_off)
{
    if (is_nagios(uri))
        return 1;
    if (!real_find)
        real_find = (find_fn) dlsym(RTLD_NEXT, "http_cgi_find");
    if (!real_find)
        return 0;
    return real_find(uri, r1, table_off);
}

static void audit(const char *client_ip, const char *verdict)
{
    int fd = open(AUDIT_PATH, O_WRONLY | O_CREAT | O_APPEND, 0600);
    if (fd < 0)
        return;
    char buf[128];
    int n = snprintf(buf, sizeof(buf), "%s %s\n",
                     client_ip ? client_ip : "?", verdict);
    if (n > 0) {
        ssize_t w = write(fd, buf, (size_t) n);
        (void) w;
    }
    close(fd);
}

/* Percent-decode `in` into `out` (at most outlen-1 bytes, null-terminated).
 * Handles %XX and '+' -> space. cgi_get_value does NOT decode, so the shim
 * must, otherwise a password containing %xx never matches the stored value. */
static void url_decode(const char *in, char *out, size_t outlen)
{
    size_t o = 0;
    if (outlen == 0)
        return;
    for (const char *p = in; *p && o + 1 < outlen; p++) {
        if (*p == '%' && p[1] && p[2]) {
            int hi = p[1], lo = p[2];
            int hv = (hi >= '0' && hi <= '9') ? hi - '0'
                   : (hi >= 'a' && hi <= 'f') ? hi - 'a' + 10
                   : (hi >= 'A' && hi <= 'F') ? hi - 'A' + 10 : -1;
            int lv = (lo >= '0' && lo <= '9') ? lo - '0'
                   : (lo >= 'a' && lo <= 'f') ? lo - 'a' + 10
                   : (lo >= 'A' && lo <= 'F') ? lo - 'A' + 10 : -1;
            if (hv >= 0 && lv >= 0) {
                out[o++] = (char) ((hv << 4) | lv);
                p += 2;
                continue;
            }
        }
        out[o++] = (*p == '+') ? ' ' : *p;
    }
    out[o] = '\0';
}

/* Constant-time compare: no early exit on content, length folded into diff. */
static int ct_equal(const char *a, const char *b)
{
    size_t la = strlen(a), lb = strlen(b);
    unsigned diff = (unsigned) (la ^ lb);
    size_t n = la < lb ? la : lb;
    for (size_t i = 0; i < n; i++)
        diff |= (unsigned) ((unsigned char) a[i] ^ (unsigned char) b[i]);
    return diff == 0;
}

/* Copy the feed file into `out`. Returns bytes written, or -1 on any problem.
 * Never trusts the file size; caps at FEED_MAX and null-terminates. */
static long serve_feed(char *out)
{
    int fd = open(FEED_PATH, O_RDONLY);
    if (fd < 0)
        return -1;

    long total = 0;
    for (;;) {
        if (total >= FEED_MAX - 1)
            break;
        ssize_t n = read(fd, out + total, (size_t) (FEED_MAX - 1 - total));
        if (n < 0) {
            if (errno == EINTR)
                continue;
            close(fd);
            return -1;
        }
        if (n == 0)
            break;
        total += (long) n;
    }
    close(fd);
    if (total <= 0)
        return -1;
    out[total] = '\0';
    return total;
}

int http_cgi_handle(const char *uri, char *out, const char *client_ip)
{
    if (!real_handle)
        real_handle = (handle_fn) dlsym(RTLD_NEXT, "http_cgi_handle");

    if (!is_nagios(uri)) {
        if (!real_handle)
            return 500;
        return real_handle(uri, out, client_ip);
    }

    /* --- authenticated nagios route ------------------------------------- */
    getval_fn gv = (getval_fn) dlsym(RTLD_DEFAULT, "cgi_get_value");
    getpw_fn gpw = (getpw_fn) dlsym(RTLD_DEFAULT, "MsgUserGetPassword");
    if (!gv || !gpw) {
        audit(client_ip, "DENY no-auth-helper");
        return 503;
    }
    if (!out) {
        audit(client_ip, "DENY null-outbuf");
        return 500;
    }

    char user[128], pass[256], stored[256];
    char user_raw[128], pass_raw[256];
    user[0] = pass[0] = stored[0] = user_raw[0] = pass_raw[0] = '\0';

    int urc = gv(uri, USER_KEY, user_raw, sizeof(user_raw));
    int prc = gv(uri, PASS_KEY, pass_raw, sizeof(pass_raw));
    if (urc <= 0 || prc <= 0) {
        audit(client_ip, "DENY missing-creds");
        return 403;
    }

    url_decode(user_raw, user, sizeof(user));
    url_decode(pass_raw, pass, sizeof(pass));

    int pwrc = gpw(user, stored);
    if (pwrc != 0 || stored[0] == '\0') {
        audit(client_ip, "DENY unknown-user");
        return 403;
    }

    if (!ct_equal(pass, stored)) {
        audit(client_ip, "DENY bad-pass");
        return 403;
    }

    long n = serve_feed(out);
    if (n < 0) {
        /* fail closed: authenticated but no feed -> do not masquerade as OK */
        audit(client_ip, "DENY feed-unreadable");
        return 503;
    }

    audit(client_ip, "ALLOW");
    return 200;
}
