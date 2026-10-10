/* deny_logic.h -- the decision table, shared by the shim and the host unit test.
 *
 * Kept separate from cve_shim.c so the logic can be unit-tested on the host.
 * The shim cannot be tested there (it needs __builtin_return_address from the
 * real caller and the real device filesystem), but the decision "given this
 * caller and this path, deny or allow" is pure and must be verified before we
 * ever put it on hardware.
 *
 * Requires: RA_PLAYBACK, RA_CFGDL_FOPEN defined by the includer.
 * Provides: sensitive_basename(), from_handler(), deny_for().
 */

/* Paths these handlers must never reach. Matched as a PATH COMPONENT SUFFIX
   against the RESOLVED path, so the /etc/passwd -> /tmp/passwd symlink on
   this device cannot smuggle the credential file past a raw-string check.
   Suffix (not substring) so /tmp/passwd.txt or rec_config.xml.bak is not
   swept up by accident. */
static const char *const bad_path[] = {
    "/passwd",            /* /etc/passwd, /tmp/passwd */
    "/passwd_sys",        /* /system/etc/passwd_sys */
    "/shadow",
    "/config.xml",
    "/ConfigFile.ini",
    "/https.key",
    "/https.pwd",
    "/encript.dat",
    "/mtdblock",
    "/proc/kcore",
    "/dev/mem",
    NULL
};

static int sensitive_basename(const char *p) {
    size_t n;
    if (!p) return 0;
    n = strlen(p);
    for (int i = 0; bad_path[i]; i++) {
        size_t bl = strlen(bad_path[i]);
        if (n >= bl && strcmp(p + n - bl, bad_path[i]) == 0) return 1;
    }
    return 0;
}

/* Is this call coming from one of the known-vulnerable handlers?
   web_server is Thumb code, so LR carries the Thumb bit and the return
   addresses captured on-device are ODD: 0x501a5, 0x500ef, 0x500ab.
   Normalise BOTH sides to even before comparing. Masking only the observed
   value -- `ra & ~1UL == 0x501a5UL` -- is provably always false against an
   odd constant, so GCC deletes the entire deny path as dead code. That
   silent failure is exactly what an earlier build of this file shipped
   with, so this normalisation is load-bearing, not cosmetic. */
static int from_handler(unsigned long ra, unsigned long want) {
    return (ra & ~1UL) == (want & ~1UL);
}

/* The core decision. Returns 1 to deny.
   Deny ONLY when a known handler reaches a sensitive file. Both the resolved
   and the raw path are checked: realpath() resolves the /etc/passwd ->
   /tmp/passwd symlink, but it fails outright for paths that do not exist and
   for some /proc magic files, so the raw string still has to be tested.

   FAILS OPEN on an unrecognised caller: a wrong or stale address costs
   protection, never availability. That is the deliberate trade -- bricking a
   customer's camera is worse than leaving one CVE partially open. */
static int deny_for(unsigned long ra, const char *path) {
    char resolved[4096];
    if (ra == 0) return 0;
    if (!(from_handler(ra, RA_PLAYBACK) ||
          from_handler(ra, RA_CFGDL_FOPEN)))
        return 0;
    resolve(path, resolved, sizeof resolved);
    if (resolved[0] && sensitive_basename(resolved)) return 1;
    if (sensitive_basename(path)) return 1;
    return 0;
}
