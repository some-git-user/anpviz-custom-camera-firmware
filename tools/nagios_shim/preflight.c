/* preflight.c -- does LD_PRELOAD work on this uClibc 1.0.31?
 *
 * Interposes getuid() and prints a marker the first time it is called.
 * If LD_PRELOAD works, `id` (which calls getuid) will show the marker on
 * stderr and report uid 4242 instead of 0.
 *
 * NB: RTLD_NEXT lives behind _GNU_SOURCE in uClibc's dlfcn.h.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <unistd.h>
#include <dlfcn.h>

static uid_t (*real_getuid)(void);
static int fired;

uid_t getuid(void)
{
    if (!real_getuid)
        real_getuid = (uid_t (*)(void)) dlsym(RTLD_NEXT, "getuid");

    if (!fired) {
        fired = 1;
        fprintf(stderr, "[preflight] LD_PRELOAD ACTIVE (real getuid=%p)\n",
                (void *) real_getuid);
    }
    /* return a distinctive uid so the effect is unmistakable */
    return 4242;
}
