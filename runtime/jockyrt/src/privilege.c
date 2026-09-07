#include "jockyrt.h"

#include "jockyrt_internal.h"

#if !defined(_WIN32)

int jkf_enable_debug_privilege(void) { return JKF_E_UNSUPPORTED; }

#else

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

int jkf_enable_debug_privilege(void) {
    HANDLE token = NULL;
    if (!OpenProcessToken(GetCurrentProcess(),
                          TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token)) {
        jkf__set_os_error(GetLastError());
        return JKF_E_OS;
    }

    LUID luid;
    if (!LookupPrivilegeValueW(NULL, SE_DEBUG_NAME, &luid)) {
        jkf__set_os_error(GetLastError());
        CloseHandle(token);
        return JKF_E_OS;
    }

    TOKEN_PRIVILEGES tp;
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    /* AdjustTokenPrivileges reports success even when it could not assign the
     * privilege; the real answer is in GetLastError(). */
    SetLastError(ERROR_SUCCESS);
    AdjustTokenPrivileges(token, FALSE, &tp, sizeof tp, NULL, NULL);
    const DWORD adjustErr = GetLastError();
    CloseHandle(token);

    if (adjustErr == ERROR_NOT_ALL_ASSIGNED) return 0;  /* privilege not held */
    if (adjustErr != ERROR_SUCCESS) {
        jkf__set_os_error(adjustErr);
        return JKF_E_OS;
    }
    return 1;  /* privilege held */
}

#endif /* _WIN32 */
