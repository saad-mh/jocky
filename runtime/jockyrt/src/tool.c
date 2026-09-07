#include "jockyrt.h"

#include "jockyrt_internal.h"

#include <stdint.h>
#include <string.h>

#if !defined(_WIN32)

int jkf_args(void *buf, uint64_t cap) {
    (void)buf;
    (void)cap;
    return JKF_E_UNSUPPORTED;
}
int jkf_process_name(uint32_t pid, void *buf, uint64_t cap) {
    (void)pid;
    (void)buf;
    (void)cap;
    return JKF_E_UNSUPPORTED;
}
int jkf_pid_by_name(const char *name) {
    (void)name;
    return JKF_E_UNSUPPORTED;
}

#else

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <tlhelp32.h>

/* The CRT exposes the parsed command line through these accessors even from a
 * function with no argv of its own. */
extern int *__p___argc(void);
extern char ***__p___argv(void);

int jkf_args(void *buf, uint64_t cap) {
    if (!buf) return JKF_E_INVAL;
    const int argc = *__p___argc();
    char **argv = *__p___argv();
    char *out = (char *)buf;
    uint64_t used = 0;
    for (int i = 0; i < argc; ++i) {
        const size_t n = strlen(argv[i]) + 1;
        if (used + n > cap) return JKF_E_TOOSMALL;
        memcpy(out + used, argv[i], n);
        used += n;
    }
    return argc;
}

int jkf_process_name(uint32_t pid, void *buf, uint64_t cap) {
    if (!buf) return JKF_E_INVAL;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) {
        jkf__set_os_error(GetLastError());
        return JKF_E_OS;
    }
    int rc = JKF_E_NOTFOUND;
    PROCESSENTRY32W pe;
    pe.dwSize = sizeof pe;
    if (Process32FirstW(snap, &pe)) {
        do {
            if (pe.th32ProcessID != (DWORD)pid) continue;
            const int need = WideCharToMultiByte(CP_UTF8, 0, pe.szExeFile, -1,
                                                 NULL, 0, NULL, NULL);
            if (need <= 0) {
                rc = JKF_E_OS;
            } else if ((uint64_t)need > cap) {
                rc = JKF_E_TOOSMALL;
            } else {
                WideCharToMultiByte(CP_UTF8, 0, pe.szExeFile, -1, (char *)buf,
                                    need, NULL, NULL);
                rc = need - 1;
            }
            break;
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
    return rc;
}

int jkf_pid_by_name(const char *name) {
    if (!name) return JKF_E_INVAL;
    wchar_t wname[MAX_PATH];
    if (MultiByteToWideChar(CP_UTF8, 0, name, -1, wname, MAX_PATH) <= 0)
        return JKF_E_INVAL;

    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) {
        jkf__set_os_error(GetLastError());
        return JKF_E_OS;
    }
    int rc = JKF_E_NOTFOUND;
    PROCESSENTRY32W pe;
    pe.dwSize = sizeof pe;
    if (Process32FirstW(snap, &pe)) {
        do {
            if (_wcsicmp(pe.szExeFile, wname) == 0) {
                rc = (int)pe.th32ProcessID;
                break;
            }
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
    return rc;
}

#endif /* _WIN32 */
