/* authprobe.c -- decisive test for Nagios phase 2.
 *
 * Question: can a STANDALONE process dlopen the vendor's libcgibin_curl.so and
 * call cgi_is_valid_username_password() to authenticate against the manage-user
 * database, WITHOUT the library being initialised by InitHttpCgi?
 *
 * If yes -> a small standalone authenticated server can reuse the vendor user DB
 *           with zero risk to web_server (no LD_PRELOAD, no handler ABI).
 * If no -> phase 2 requires the riskier LD_PRELOAD shim inside web_server.
 *
 * Usage: authprobe <username> <password>
 * Prints the raw return value of each auth entry point.
 */
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef int (*auth_fn)(const char *, const char *, const char *);

static const char *LIB = "libcgibin_curl.so";

static void try_fn(void *h, const char *name, const char *user, const char *pass)
{
    auth_fn f = (auth_fn) dlsym(h, name);
    if (!f) {
        printf("  %-34s dlsym FAILED (%s)\n", name, dlerror());
        return;
    }
    /* source string mirrors what the CGI layer passes (the route name) */
    int r = f(user, pass, "authprobe");
    printf("  %-34s -> %d  (%s)\n", name, r,
           r >= 0 ? "ACCEPTED" : "REJECTED");
}

int main(int argc, char **argv)
{
    if (argc < 3) {
        fprintf(stderr, "usage: %s <username> <password>\n", argv[0]);
        return 2;
    }
    const char *user = argv[1];
    const char *pass = argv[2];

    printf("dlopen(%s)...\n", LIB);
    void *h = dlopen(LIB, RTLD_NOW | RTLD_GLOBAL);
    if (!h) {
        /* try the absolute path in case LD_LIBRARY_PATH is not set */
        h = dlopen("/opt/ch/libcgibin_curl.so", RTLD_NOW | RTLD_GLOBAL);
    }
    if (!h) {
        printf("  dlopen failed: %s\n", dlerror());
        return 1;
    }
    printf("  dlopen OK\n");

    printf("auth entry points for user=%s:\n", user);
    try_fn(h, "cgi_is_valid_username_password", user, pass);
    try_fn(h, "cgi_is_valid_uid", user, pass);
    try_fn(h, "cgi_is_valid_uid_or_username", user, pass);

    dlclose(h);
    return 0;
}
