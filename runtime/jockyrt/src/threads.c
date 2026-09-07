#include "jockyrt.h"

#include "jockyrt_internal.h"

#include <stdint.h>
#include <stdlib.h>

#if !defined(_WIN32)

int jkf_thread_count(uint32_t pid) {
    (void)pid;
    return JKF_E_UNSUPPORTED;
}
int jkf_threads(uint32_t pid, void *out, uint64_t cap) {
    (void)pid;
    (void)out;
    (void)cap;
    return JKF_E_UNSUPPORTED;
}

#else

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <tlhelp32.h>

/* The SDK's <winternl.h> does not always declare these, so spell out the
 * stable public layout we need (only TebBaseAddress is read). */
typedef struct {
    HANDLE UniqueProcess;
    HANDLE UniqueThread;
} JKF_CLIENT_ID;

typedef struct {
    LONG ExitStatus;  /* NTSTATUS */
    PVOID TebBaseAddress;
    JKF_CLIENT_ID ClientId;
    ULONG_PTR AffinityMask;
    LONG Priority;
    LONG BasePriority;
} JKF_THREAD_BASIC_INFORMATION;

/* NtQueryInformationThread(handle, class, buf, len, retlen). Resolved from
 * ntdll on first use. */
typedef LONG(WINAPI *NtQueryThread_fn)(HANDLE, int, PVOID, ULONG, PULONG);

static NtQueryThread_fn nt_query_thread(void) {
    static NtQueryThread_fn fn = NULL;
    static int tried = 0;
    if (!tried) {
        tried = 1;
        HMODULE nt = GetModuleHandleW(L"ntdll.dll");
        if (nt)
            fn = (NtQueryThread_fn)(void *)GetProcAddress(
                nt, "NtQueryInformationThread");
    }
    return fn;
}

enum {
    JKF_ThreadBasicInformation = 0,
    JKF_ThreadWin32StartAddress = 9
};

static int cmp_by_tid(const void *a, const void *b) {
    const uint32_t ta = ((const JkfThreadRecord *)a)->tid;
    const uint32_t tb = ((const JkfThreadRecord *)b)->tid;
    return (ta > tb) - (ta < tb);
}

static void fill_thread(JkfThreadRecord *r, DWORD tid) {
    r->version = JKF_THREAD_RECORD_VERSION;
    r->tid = tid;
    r->flags = 0;
    r->reserved = 0;
    r->startAddr = 0;
    r->teb = 0;

    NtQueryThread_fn q = nt_query_thread();
    HANDLE th = OpenThread(THREAD_QUERY_INFORMATION, FALSE, tid);
    if (!th || !q) {
        if (th) CloseHandle(th);
        return;
    }
    PVOID sa = NULL;
    if (q(th, JKF_ThreadWin32StartAddress, &sa, sizeof sa, NULL) == 0)
        r->startAddr = (uint64_t)(uintptr_t)sa;
    JKF_THREAD_BASIC_INFORMATION tbi;
    if (q(th, JKF_ThreadBasicInformation, &tbi, sizeof tbi, NULL) == 0)
        r->teb = (uint64_t)(uintptr_t)tbi.TebBaseAddress;
    CloseHandle(th);
}

static int enumerate(uint32_t pid, JkfThreadRecord *out, uint64_t capBytes) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snap == INVALID_HANDLE_VALUE) {
        jkf__set_os_error(GetLastError());
        return JKF_E_OS;
    }

    const uint64_t capRec =
        out ? capBytes / (uint64_t)sizeof(JkfThreadRecord) : 0;
    uint64_t total = 0;
    int overflowed = 0;

    THREADENTRY32 te;
    te.dwSize = sizeof te;
    if (Thread32First(snap, &te)) {
        do {
            if (te.th32OwnerProcessID != (DWORD)pid) continue;
            if (out && total < capRec) {
                fill_thread(&out[total], te.th32ThreadID);
            } else if (out) {
                overflowed = 1;
            }
            ++total;
        } while (Thread32Next(snap, &te));
    }
    CloseHandle(snap);

    if (out && overflowed) return JKF_E_TOOSMALL;
    if (out && total > 1)
        qsort(out, (size_t)total, sizeof(JkfThreadRecord), cmp_by_tid);
    return (int)total;
}

int jkf_thread_count(uint32_t pid) { return enumerate(pid, NULL, 0); }

int jkf_threads(uint32_t pid, void *out, uint64_t cap) {
    if (!out || cap < sizeof(JkfThreadRecord)) return JKF_E_INVAL;
    return enumerate(pid, (JkfThreadRecord *)out, cap);
}

#endif /* _WIN32 */
