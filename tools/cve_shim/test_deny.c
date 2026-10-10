/* Host-side unit test for the deny decision table.
 *
 * We cannot fake __builtin_return_address(), so the shim's RA constants are
 * made overridable at compile time and the decision function is exposed via
 * a test-only include. This verifies the LOGIC (which path + which caller =
 * deny/allow) without needing the real binary or a device.
 *
 * Build & run:  make -f Makefile.test && ./test_deny
 */
#define _GNU_SOURCE
#include <assert.h>
#include <stdio.h>
#include <string.h>

/* Override the RA constants with values the test controls, then pull in the
   real decision code so we are testing the shipped logic, not a copy. */
#define RA_PLAYBACK 0x501a5UL
#define RA_CFGDL_FOPEN 0x500efUL
#define RA_CFGDL_POPEN 0x500abUL

/* Stub resolver: the host has no /etc/passwd -> /tmp/passwd symlink, so a
   real realpath() would not reproduce the device topology under test. Must
   be defined before deny_logic.h, which calls it. */
static void resolve(const char *p, char *out, unsigned long n) {
    /* Mirror the device symlink: /etc/passwd -> /tmp/passwd */
    if (strcmp(p, "/etc/passwd") == 0) { snprintf(out, n, "/tmp/passwd"); return; }
    if (strcmp(p, "/etc/passwd_sys") == 0) { snprintf(out, n, "/system/etc/passwd_sys"); return; }
    snprintf(out, n, "%s", p);
}
#include "deny_logic.h"

static int checks = 0, fails = 0;
static void expect(const char *what, int ra, const char *path, int want) {
    int got = deny_for((unsigned long) ra, path);
    checks++;
    if (got != want) {
        fails++;
        printf("FAIL %-34s ra=%#x path=%-34s want=%d got=%d\n",
               what, ra, path, want, got);
    } else {
        printf("ok   %-34s ra=%#x path=%-34s -> %s\n",
               what, ra, path, got ? "DENY" : "allow");
    }
}

int main(void) {
    /* --- the /playback/ handler must be denied for secrets ------------- */
    expect("playback -> /etc/passwd", 0x501a5, "/etc/passwd", 1);
    expect("playback -> /tmp/passwd (symlink target)", 0x501a5, "/tmp/passwd", 1);
    expect("playback -> /etc/passwd_sys", 0x501a5, "/etc/passwd_sys", 1);
    expect("playback -> /mnt/nand/config.xml", 0x501a5, "/mnt/nand/config.xml", 1);
    expect("playback -> ConfigFile.ini", 0x501a5, "/mnt/nand/ConfigFile.ini", 1);
    expect("playback -> https.key", 0x501a5, "/opt/ch/https.key", 1);
    expect("playback -> /dev/mem", 0x501a5, "/dev/mem", 1);

    /* --- the config-download fopen must be denied ---------------------- */
    expect("cfgdl -> config.xml", 0x500ef, "/mnt/nand/config.xml", 1);

    /* --- the SAME paths from a NON-handler caller must be ALLOWED ------ *
     * This is the regression guard: web_server reads /etc/passwd during
     * normal login from 0x38fc5. Denying that would break the product. */
    expect("login(0x38fc5) -> /etc/passwd", 0x38fc5, "/etc/passwd", 0);
    expect("normal(0x38c75) -> /tmp/passwd", 0x38c75, "/tmp/passwd", 0);
    expect("normal -> config.xml", 0x12345, "/mnt/nand/config.xml", 0);
    expect("normal -> /dev/mem", 0x12345, "/dev/mem", 0);

    /* --- handler must still be able to serve NON-sensitive files ------- *
     * /playback/ legitimately serves recordings; those are not secrets. */
    expect("playback -> recording.mp4", 0x501a5, "/mnt/mmc0/2026/rec/recording.mp4", 0);
    expect("playback -> /var/www/index.html", 0x501a5, "/var/www/index.html", 0);
    expect("playback -> timezone", 0x501a5, "/mnt/nand/timezone", 0);

    /* --- suffix matching must not over-block --------------------------- */
    expect("playback -> passwd.txt (not a secret)", 0x501a5, "/tmp/passwd.txt", 0);
    expect("playback -> mypasswd (not /passwd)", 0x501a5, "/tmp/mypasswd", 0);

    /* --- odd/even RA: Thumb sets bit 0; both forms must gate ---------- */
    expect("playback odd RA", 0x501a5, "/etc/passwd", 1);
    expect("playback even RA", 0x501a4, "/etc/passwd", 1);

    printf("\n%d checks, %d failures\n", checks, fails);
    return fails ? 1 : 0;
}
