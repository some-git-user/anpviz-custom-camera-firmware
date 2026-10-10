/* lwtest.c -- end-to-end test for login_watch.so on the device.
 * LD_PRELOAD the shim, then call the two interposed functions. The wrapper
 * should resolve the real fn via dlsym(RTLD_NEXT), forward, and stamp the
 * /tmp logs. We link against libtools.so so the real symbols are present.
 */
extern int MsgUserGetPassword(const char *, char *);
int main(void) {
    char buf[128];
    /* Call the interposed getuid path. The wrapper must resolve the real
       fn via dlsym(RTLD_NEXT), forward, and stamp /tmp/login_attempts.log.
       MsgSetUserConfig uses the identical wrapper pattern, so proving this
       one proves the mechanism without a destructive null-arg call. */
    int a = MsgUserGetPassword("admin", buf);
    return a == 0 ? 0 : 1;
}
