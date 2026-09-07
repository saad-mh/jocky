#include "jockyrt.h"

#include "jockyrt_internal.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#if !defined(_WIN32)

int jkf_module_count(int h) {
    (void)h;
    return JKF_E_UNSUPPORTED;
}
int jkf_modules(int h, void *o, uint64_t oc, void *n, uint64_t nc) {
    (void)h;
    (void)o;
    (void)oc;
    (void)n;
    (void)nc;
    return JKF_E_UNSUPPORTED;
}
int jkf_mapped_name(int h, uint64_t a, void *n, uint64_t nc) {
    (void)h;
    (void)a;
    (void)n;
    (void)nc;
    return JKF_E_UNSUPPORTED;
}

#else

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <psapi.h>

/* Append a UTF-8 copy of the NUL-terminated `w` into blob[*used .. cap).
 * Returns the offset it landed at, or -1 if it does not fit. */
static long blob_put(char *blob, uint64_t cap, uint64_t *used, const wchar_t *w) {
    const int need = WideCharToMultiByte(CP_UTF8, 0, w, -1, NULL, 0, NULL, NULL);
    if (need <= 0) return -1;
    if (*used + (uint64_t)need > cap) return -1;
    const long off = (long)*used;
    WideCharToMultiByte(CP_UTF8, 0, w, -1, blob + *used, need, NULL, NULL);
    *used += (uint64_t)need;
    return off;
}

static int cmp_by_base(const void *a, const void *b) {
    const uint64_t ba = ((const JkfModuleRecord *)a)->base;
    const uint64_t bb = ((const JkfModuleRecord *)b)->base;
    return (ba > bb) - (ba < bb);
}

int jkf_module_count(int handle) {
    HANDLE h = (HANDLE)jkf__handle_get(handle);
    if (!h) return JKF_E_BADHANDLE;
    DWORD needed = 0;
    if (!EnumProcessModulesEx(h, NULL, 0, &needed, LIST_MODULES_ALL)) {
        jkf__set_os_error(GetLastError());
        return JKF_E_OS;
    }
    return (int)(needed / sizeof(HMODULE));
}

int jkf_modules(int handle, void *out, uint64_t outCap, void *names,
                uint64_t namesCap) {
    if (!out || !names) return JKF_E_INVAL;
    HANDLE h = (HANDLE)jkf__handle_get(handle);
    if (!h) return JKF_E_BADHANDLE;

    DWORD needed = 0;
    if (!EnumProcessModulesEx(h, NULL, 0, &needed, LIST_MODULES_ALL)) {
        jkf__set_os_error(GetLastError());
        return JKF_E_OS;
    }
    const DWORD count = needed / (DWORD)sizeof(HMODULE);
    if ((uint64_t)count * sizeof(JkfModuleRecord) > outCap) return JKF_E_TOOSMALL;

    HMODULE *mods = (HMODULE *)malloc(needed ? needed : sizeof(HMODULE));
    if (!mods) return JKF_E_NOMEM;
    if (!EnumProcessModulesEx(h, mods, needed, &needed, LIST_MODULES_ALL)) {
        free(mods);
        jkf__set_os_error(GetLastError());
        return JKF_E_OS;
    }

    JkfModuleRecord *rec = (JkfModuleRecord *)out;
    uint64_t blobUsed = 0;
    /* EnumProcessModules puts the process image first. */
    uint64_t mainBase = 0;

    for (DWORD i = 0; i < count; ++i) {
        MODULEINFO mi;
        memset(&mi, 0, sizeof mi);
        GetModuleInformation(h, mods[i], &mi, sizeof mi);

        wchar_t path[MAX_PATH * 4];
        wchar_t name[MAX_PATH];
        if (GetModuleFileNameExW(h, mods[i], path,
                                 (DWORD)(sizeof path / sizeof *path)) == 0)
            path[0] = 0;
        if (GetModuleBaseNameW(h, mods[i], name,
                               (DWORD)(sizeof name / sizeof *name)) == 0)
            name[0] = 0;

        const long nameOff = blob_put((char *)names, namesCap, &blobUsed, name);
        const long pathOff = blob_put((char *)names, namesCap, &blobUsed, path);
        if (nameOff < 0 || pathOff < 0) {
            free(mods);
            return JKF_E_TOOSMALL;
        }

        rec[i].version = JKF_MODULE_RECORD_VERSION;
        rec[i].nameOff = (uint32_t)nameOff;
        rec[i].pathOff = (uint32_t)pathOff;
        rec[i].flags = 0;
        rec[i].base = (uint64_t)(uintptr_t)mi.lpBaseOfDll;
        rec[i].size = (uint64_t)mi.SizeOfImage;
        rec[i].entryPoint = (uint64_t)(uintptr_t)mi.EntryPoint;
        if (i == 0) mainBase = rec[i].base;
    }
    free(mods);

    if (count > 1)
        qsort(rec, count, sizeof(JkfModuleRecord), cmp_by_base);
    for (DWORD i = 0; i < count; ++i)
        rec[i].flags = (rec[i].base == mainBase) ? JKF_MOD_MAIN : 0u;

    return (int)count;
}

int jkf_mapped_name(int handle, uint64_t addr, void *names, uint64_t namesCap) {
    if (!names) return JKF_E_INVAL;
    HANDLE h = (HANDLE)jkf__handle_get(handle);
    if (!h) return JKF_E_BADHANDLE;

    wchar_t dev[MAX_PATH * 4];
    const DWORD n = GetMappedFileNameW(h, (LPVOID)(uintptr_t)addr, dev,
                                       (DWORD)(sizeof dev / sizeof *dev));
    if (n == 0) return JKF_E_NOTFOUND;  /* not file-backed */

    const int need = WideCharToMultiByte(CP_UTF8, 0, dev, -1, NULL, 0, NULL, NULL);
    if (need <= 0) return JKF_E_OS;
    if ((uint64_t)need > namesCap) return JKF_E_TOOSMALL;
    WideCharToMultiByte(CP_UTF8, 0, dev, -1, (char *)names, need, NULL, NULL);
    return need - 1;  /* length without the NUL */
}

#endif /* _WIN32 */
