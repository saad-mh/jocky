/* jockyrt smoke test - runs under ctest as `jockyrt_smoke`.
 *
 * Checks the flat ABI contract (record sizes, versions, ordering) and the two
 * functions that exist so far against the real machine: our own pid must show
 * up in jkf_processes(), and jkf_enable_debug_privilege() must not error. */

#include "jockyrt.h"

#include <stdio.h>
#include <stdlib.h>

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

    const int n = jkf_process_count();
    check(n > 0, "jkf_process_count > 0");
    if (n <= 0) {
        printf("\ncannot continue (process_count=%d, last_os_error=%u)\n", n,
               jkf_last_os_error());
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
    JkfProcessRecord one;
    const int tooSmall = jkf_processes(&one, sizeof one);
    check(tooSmall == JKF_E_TOOSMALL || got == 1,
          "one-record buffer -> JKF_E_TOOSMALL");

    const int priv = jkf_enable_debug_privilege();
    check(priv >= 0, "jkf_enable_debug_privilege did not error");
    printf("     (debug privilege %s)\n",
           priv > 0 ? "held" : "not held - run elevated for the full walk");

    free(buf);
    printf(g_failures ? "\n%d failure(s)\n" : "\nall good\n", g_failures);
    return g_failures ? 1 : 0;
}
