#include "jockyrt.h"

#include "jockyrt_internal.h"

#include <stdlib.h>

#if !defined(_WIN32)

int jkf_process_count(void) { return JKF_E_UNSUPPORTED; }
int jkf_processes(void *out, uint64_t cap) {
    (void)out;
    (void)cap;
    return JKF_E_UNSUPPORTED;
}

#else

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <tlhelp32.h>

static int cmp_by_pid(const void *a, const void *b) {
    const uint32_t pa = ((const JkfProcessRecord *)a)->pid;
    const uint32_t pb = ((const JkfProcessRecord *)b)->pid;
    return (pa > pb) - (pa < pb);
}

static uint32_t proc_flags(DWORD pid) {
    uint32_t flags = JKF_PROC_ELEVATION_UNK;
    HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (h) {
        BOOL wow = FALSE;
        if (IsWow64Process(h, &wow) && wow) flags |= JKF_PROC_WOW64;
        CloseHandle(h);
    }
    return flags;
}

/* One pass over a TH32CS_SNAPPROCESS snapshot. When `out` is non-null, records
 * are written while they fit. Always returns the total process count (so the
 * caller can size a buffer), or JKF_E_OS / JKF_E_TOOSMALL. */
static int enumerate(JkfProcessRecord *out, uint64_t capBytes) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) {
        jkf__set_os_error(GetLastError());
        return JKF_E_OS;
    }

    const uint64_t capRecords =
        out ? capBytes / (uint64_t)sizeof(JkfProcessRecord) : 0;
    uint64_t total = 0;
    int overflowed = 0;

    PROCESSENTRY32W pe;
    pe.dwSize = sizeof pe;
    if (Process32FirstW(snap, &pe)) {
        do {
            if (out && total < capRecords) {
                JkfProcessRecord *r = &out[total];
                r->version = JKF_PROCESS_RECORD_VERSION;
                r->pid = pe.th32ProcessID;
                r->ppid = pe.th32ParentProcessID;
                DWORD sid = 0;
                ProcessIdToSessionId(pe.th32ProcessID, &sid);
                r->sessionId = sid;
                r->flags = proc_flags(pe.th32ProcessID);
            } else if (out) {
                overflowed = 1;
            }
            ++total;
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);

    if (out && overflowed) return JKF_E_TOOSMALL;
    if (out && total > 1)
        qsort(out, (size_t)total, sizeof(JkfProcessRecord), cmp_by_pid);
    return (int)total;
}

int jkf_process_count(void) { return enumerate(NULL, 0); }

int jkf_processes(void *out, uint64_t cap) {
    if (!out || cap < sizeof(JkfProcessRecord)) return JKF_E_INVAL;
    return enumerate((JkfProcessRecord *)out, cap);
}

#endif /* _WIN32 */
