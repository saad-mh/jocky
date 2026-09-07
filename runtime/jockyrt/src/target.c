#include "jockyrt.h"

#include "jockyrt_internal.h"

#include <stdint.h>

#if !defined(_WIN32)

int jkf_open(uint32_t pid, int want_write, void *o, uint64_t c) {
    (void)pid;
    (void)want_write;
    (void)o;
    (void)c;
    return JKF_E_UNSUPPORTED;
}
int jkf_close(int h) {
    (void)h;
    return JKF_E_UNSUPPORTED;
}
int jkf_region_at(int h, uint64_t a, void *o, uint64_t c) {
    (void)h;
    (void)a;
    (void)o;
    (void)c;
    return JKF_E_UNSUPPORTED;
}
int jkf_read(int h, uint64_t a, void *b, uint64_t l) {
    (void)h;
    (void)a;
    (void)b;
    (void)l;
    return JKF_E_UNSUPPORTED;
}

#else

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

/* ---- R.3  open / close ------------------------------------------------ */

int jkf_open(uint32_t pid, int want_write, void *accessOut, uint64_t accessCap) {
    if (pid == 0) return JKF_E_INVAL;

    struct {
        DWORD mask;
        uint32_t level;
    } tries[3];
    int nt = 0;
    if (want_write) {
        tries[nt].mask = PROCESS_QUERY_INFORMATION | PROCESS_VM_READ |
                         PROCESS_VM_WRITE | PROCESS_VM_OPERATION;
        tries[nt++].level = JKF_ACCESS_READ_WRITE;
    }
    tries[nt].mask = PROCESS_QUERY_INFORMATION | PROCESS_VM_READ;
    tries[nt++].level = JKF_ACCESS_READ;
    tries[nt].mask = PROCESS_QUERY_LIMITED_INFORMATION;
    tries[nt++].level = JKF_ACCESS_QUERY;

    HANDLE h = NULL;
    uint32_t level = JKF_ACCESS_NONE;
    DWORD grantedMask = 0, lastErr = 0;
    for (int i = 0; i < nt; ++i) {
        h = OpenProcess(tries[i].mask, FALSE, pid);
        if (h) {
            level = tries[i].level;
            grantedMask = tries[i].mask;
            break;
        }
        lastErr = GetLastError();
    }
    if (!h) {
        jkf__set_os_error(lastErr);
        if (lastErr == ERROR_INVALID_PARAMETER) return JKF_E_NOTFOUND;
        if (lastErr == ERROR_ACCESS_DENIED) return JKF_E_ACCESS;
        return JKF_E_OS;
    }

    const int token = jkf__handle_alloc(h);
    if (token < 0) {
        CloseHandle(h);
        return token;
    }

    if (accessOut && accessCap >= sizeof(JkfAccessRecord)) {
        JkfAccessRecord *r = (JkfAccessRecord *)accessOut;
        r->version = JKF_ACCESS_RECORD_VERSION;
        r->level = level;
        r->grantedMask = (uint32_t)grantedMask;
        r->reserved = 0;
    }
    return token;
}

int jkf_close(int handle) {
    HANDLE h = (HANDLE)jkf__handle_get(handle);
    if (!h) return JKF_E_BADHANDLE;
    CloseHandle(h);
    return jkf__handle_release(handle);
}

/* ---- R.4  region walk ------------------------------------------------- */

int jkf_region_at(int handle, uint64_t addr, void *out, uint64_t cap) {
    if (!out || cap < sizeof(JkfRegionRecord)) return JKF_E_INVAL;
    HANDLE h = (HANDLE)jkf__handle_get(handle);
    if (!h) return JKF_E_BADHANDLE;

    MEMORY_BASIC_INFORMATION mbi;
    if (VirtualQueryEx(h, (LPCVOID)(uintptr_t)addr, &mbi, sizeof mbi) == 0) {
        const DWORD e = GetLastError();
        if (e == ERROR_INVALID_PARAMETER) return 0;  /* past the address space */
        jkf__set_os_error(e);
        return JKF_E_OS;
    }

    JkfRegionRecord *r = (JkfRegionRecord *)out;
    r->version = JKF_REGION_RECORD_VERSION;
    r->state = mbi.State;
    r->type = (mbi.State == MEM_FREE) ? 0u : mbi.Type;
    r->protect = mbi.Protect;
    r->allocProtect = mbi.AllocationProtect;
    r->reserved = 0;
    r->base = (uint64_t)(uintptr_t)mbi.BaseAddress;
    r->size = (uint64_t)mbi.RegionSize;
    r->allocBase = (uint64_t)(uintptr_t)mbi.AllocationBase;
    return 1;
}

/* ---- R.5  read ----------------------------------------------------- */

int jkf_read(int handle, uint64_t addr, void *buf, uint64_t len) {
    if (!buf) return JKF_E_INVAL;
    if (len == 0) return 0;
    if (len > 0x7fffffffull) len = 0x7fffffffull;  /* int32 return */
    HANDLE h = (HANDLE)jkf__handle_get(handle);
    if (!h) return JKF_E_BADHANDLE;

    const uint64_t CHUNK = 1ull << 20;  /* 1 MiB */
    uint64_t done = 0;
    char *dst = (char *)buf;

    while (done < len) {
        const uint64_t cur = addr + done;
        uint64_t want = len - done;
        if (want > CHUNK) want = CHUNK;

        MEMORY_BASIC_INFORMATION mbi;
        if (VirtualQueryEx(h, (LPCVOID)(uintptr_t)cur, &mbi, sizeof mbi) == 0)
            break;
        if (mbi.State != MEM_COMMIT) break;               /* reserved / free   */
        if (mbi.Protect & (PAGE_GUARD | PAGE_NOACCESS)) break;

        const uint64_t regionEnd =
            (uint64_t)(uintptr_t)mbi.BaseAddress + (uint64_t)mbi.RegionSize;
        if (cur + want > regionEnd) want = regionEnd - cur;
        if (want == 0) break;

        SIZE_T nread = 0;
        const BOOL ok = ReadProcessMemory(h, (LPCVOID)(uintptr_t)cur,
                                          dst + done, (SIZE_T)want, &nread);
        done += nread;
        if (!ok || nread < want) break;  /* partial copy or blocked - stop */
    }

    if (done == 0) return JKF_E_FAULT;
    return (int)done;
}

#endif /* _WIN32 */
