/* preflight2.c -- pass-through interposer for http_cgi_handle.
 *
 * Purpose: confirm empirically, on the live device, that
 *   (a) LD_PRELOAD can interpose http_cgi_handle (the call in http_cgi_bin
 *       goes through the PLT, so it should), and
 *   (b) the real argument values match what static analysis says:
 *         r0 = route name        (e.g. "/cgi-bin/getinfo")
 *         r1 = context/conn ptr
 *         r2 = full request URI  (path + "?query")
 *         r3 = caller-allocated output buffer (handlers sprintf into this)
 *
 * This shim does NOTHING except log and forward. It passes the four arguments
 * through in the same registers, so even if our type guesses are wrong the
 * forwarding is still correct -- this cannot break dispatch.
 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>

typedef int (*handle_fn)(const char *, const void *, const char *, char *);
static handle_fn real_handle;

int http_cgi_handle(const char *route, const void *ctx, const char *url,
                    char *out)
{
    if (!real_handle)
        real_handle = (handle_fn) dlsym(RTLD_NEXT, "http_cgi_handle");

    /* Append one line per dispatch. O_APPEND so concurrent writers interleave
     * whole lines; keep it short because this is on the request hot path. */
    int fd = open("/tmp/shim.log", O_WRONLY | O_CREAT | O_APPEND, 0644);
    if (fd >= 0) {
        char buf[512];
        int n = snprintf(buf, sizeof(buf),
                        "route=%s ctx=%p url=%s out=%p\n",
                        route ? route : "(null)", ctx,
                        url ? url : "(null)", (void *) out);
        if (n > 0) {
            ssize_t w = write(fd, buf, (size_t) n);
            (void) w;
        }
        close(fd);
    }

    if (!real_handle)
        return 500;
    return real_handle(route, ctx, url, out);
}
