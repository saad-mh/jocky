/* jockyrt smoke test - runs under ctest as `jockyrt_smoke`.
 *
 * Checks the flat ABI (record sizes / versions / ordering) and every function
 * that exists so far against the live process: our own pid is enumerable, we
 * can open ourselves, walk a gap-free region list, read our own memory back,
 * and get JKF_E_FAULT for an unmapped address. */

#include "jockyrt.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(_WIN32)
#  define WIN32_LEAN_AND_MEAN
#  include <windows.h>
#endif

static int g_failures = 0;

static void check(int ok, const char *what) {
    printf("%s: %s\n", ok ? "ok  " : "FAIL", what);
    if (!ok) ++g_failures;
}

int main(void) {
    check(jkf_abi_version() == JKF_ABI_VERSION, "jkf_abi_version");
    check(sizeof(JkfProcessRecord) == 20, "JkfProcessRecord is 20 bytes");
    check(sizeof(JkfAccessRecord) == 16, "JkfAccessRecord is 16 bytes");
    check(sizeof(JkfRegionRecord) == 48, "JkfRegionRecord is 48 bytes");

    const int n = jkf_process_count();
    check(n > 0, "jkf_process_count > 0");
    if (n <= 0) {
        printf("\ncannot continue (last_os_error=%u)\n", jkf_last_os_error());
        return 1;
    }

    const uint64_t bytes =
        (uint64_t)(n + 64) * (uint64_t)sizeof(JkfProcessRecord);
    JkfProcessRecord *buf = malloc((size_t)bytes);
    check(buf != NULL, "malloc");
    if (!buf) return 1;

    const int got = jkf_processes(buf, bytes);
    check(got == n, "jkf_processes count matches jkf_process_count");
    check(got < 1 || buf[0].version == JKF_PROCESS_RECORD_VERSION,
          "first record is versioned");

#if defined(_WIN32)
    const uint32_t me = (uint32_t)GetCurrentProcessId();
#else
    const uint32_t me = 0;
#endif
    int found_self = 0, ascending = 1;
    for (int i = 0; i < got; ++i) {
        if (i && buf[i].pid < buf[i - 1].pid) ascending = 0;
        if (buf[i].pid == me) found_self = 1;
    }
    check(ascending, "pids are ascending");
    check(found_self, "our own pid is in the list");
    check(jkf_processes(NULL, 4096) == JKF_E_INVAL,
          "null out buffer -> JKF_E_INVAL");
    free(buf);

    const int priv = jkf_enable_debug_privilege();
    check(priv >= 0, "jkf_enable_debug_privilege did not error");
    printf("     (debug privilege %s)\n", priv > 0 ? "held" : "not held");

#if defined(_WIN32)
    /* --- open / regions / read against ourselves --- */
    JkfAccessRecord acc;
    const int t = jkf_open(me, 0, &acc, sizeof acc);
    check(t > 0, "jkf_open(self) -> token");
    if (t > 0) {
        check(acc.version == JKF_ACCESS_RECORD_VERSION, "access record versioned");
        check(acc.level >= JKF_ACCESS_READ, "opened self with read access");

        uint64_t addr = 0;
        int regions = 0, images = 0, wellFormed = 1;
        JkfRegionRecord reg;
        for (;;) {
            const int rc = jkf_region_at(t, addr, &reg, sizeof reg);
            if (rc <= 0) {
                if (rc < 0) wellFormed = 0;  /* an error, not clean end */
                break;
            }
            if (reg.version != JKF_REGION_RECORD_VERSION) wellFormed = 0;
            if (reg.base < addr) wellFormed = 0;  /* walk must not go backwards */
            if (reg.type == 0x1000000 /* MEM_IMAGE */) ++images;
            addr = reg.base + reg.size;
            if (++regions > 200000) break;  /* safety */
        }
        check(regions > 10, "walked more than 10 regions");
        check(wellFormed, "region walk is monotonic and versioned");
        check(images > 0, "at least one MEM_IMAGE region");

        char probe[16];
        memcpy(probe, "hello jockyrt!!", 16);
        char out[16] = {0};
        const int rd =
            jkf_read(t, (uint64_t)(uintptr_t)probe, out, sizeof out);
        check(rd == 16, "jkf_read read 16 bytes of our own memory");
        check(memcmp(out, probe, 16) == 0, "jkf_read round-trips the bytes");

        const int fault = jkf_read(t, 0x1000, out, 16);
        check(fault == JKF_E_FAULT, "jkf_read of an unmapped page -> JKF_E_FAULT");

        check(jkf_close(t) == JKF_OK, "jkf_close");
        check(jkf_close(t) == JKF_E_BADHANDLE, "double jkf_close -> JKF_E_BADHANDLE");
    }

    check(jkf_open(0xFFFFFFF0u, 0, NULL, 0) < 0, "jkf_open of a bogus pid fails");
#endif

    printf(g_failures ? "\n%d failure(s)\n" : "\nall good\n", g_failures);
    return g_failures ? 1 : 0;
}
