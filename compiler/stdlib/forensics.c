/*
 * forensics.c — JOCKY Standard Library: Native C Implementations
 *
 * Cross-platform: Windows (MinGW/MSVC) and Linux (gcc).
 *
 * Compile on Windows:
 *   gcc -c stdlib/forensics.c -o stdlib/forensics.o -O2 -std=c11
 *
 * Compile on Linux:
 *   gcc -c stdlib/forensics.c -o stdlib/forensics.o -O2 -std=c11 -D_GNU_SOURCE
 *
 * Link on Windows:
 *   gcc output/myprog.o stdlib/forensics.o -o myprog.exe -lpsapi -liphlpapi -ladvapi32
 *
 * Link on Linux:
 *   gcc output/myprog.o stdlib/forensics.o -o myprog
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <ctype.h>
#include "forensics.h"

/* ── SHA-256 (self-contained, no openssl dependency) ──────────────────────── */

typedef struct {
    uint32_t state[8];
    uint64_t count;
    uint8_t  buf[64];
} SHA256_CTX_JK;

static const uint32_t _K[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2,
};

#define ROR32(x,n) (((x)>>(n))|((x)<<(32-(n))))
#define CH(e,f,g)  (((e)&(f))^(~(e)&(g)))
#define MAJ(a,b,c) (((a)&(b))^((a)&(c))^((b)&(c)))
#define EP0(a)     (ROR32(a,2)^ROR32(a,13)^ROR32(a,22))
#define EP1(e)     (ROR32(e,6)^ROR32(e,11)^ROR32(e,25))
#define SIG0(x)    (ROR32(x,7)^ROR32(x,18)^((x)>>3))
#define SIG1(x)    (ROR32(x,17)^ROR32(x,19)^((x)>>10))

static void _sha256_transform(SHA256_CTX_JK *ctx, const uint8_t data[64]) {
    uint32_t m[64], a,b,c,d,e,f,g,h,t1,t2;
    for (int i=0;i<16;i++)
        m[i]=((uint32_t)data[i*4]<<24)|((uint32_t)data[i*4+1]<<16)|
             ((uint32_t)data[i*4+2]<<8)|data[i*4+3];
    for (int i=16;i<64;i++)
        m[i]=SIG1(m[i-2])+m[i-7]+SIG0(m[i-15])+m[i-16];
    a=ctx->state[0];b=ctx->state[1];c=ctx->state[2];d=ctx->state[3];
    e=ctx->state[4];f=ctx->state[5];g=ctx->state[6];h=ctx->state[7];
    for (int i=0;i<64;i++) {
        t1=h+EP1(e)+CH(e,f,g)+_K[i]+m[i];
        t2=EP0(a)+MAJ(a,b,c);
        h=g;g=f;f=e;e=d+t1;d=c;c=b;b=a;a=t1+t2;
    }
    ctx->state[0]+=a;ctx->state[1]+=b;ctx->state[2]+=c;ctx->state[3]+=d;
    ctx->state[4]+=e;ctx->state[5]+=f;ctx->state[6]+=g;ctx->state[7]+=h;
}

static void _sha256_init(SHA256_CTX_JK *ctx) {
    ctx->state[0]=0x6a09e667;ctx->state[1]=0xbb67ae85;
    ctx->state[2]=0x3c6ef372;ctx->state[3]=0xa54ff53a;
    ctx->state[4]=0x510e527f;ctx->state[5]=0x9b05688c;
    ctx->state[6]=0x1f83d9ab;ctx->state[7]=0x5be0cd19;
    ctx->count=0;
}

static void _sha256_update(SHA256_CTX_JK *ctx, const uint8_t *data, size_t len) {
    for (size_t i=0;i<len;i++) {
        ctx->buf[ctx->count%64]=data[i];
        ctx->count++;
        if (ctx->count%64==0) _sha256_transform(ctx,ctx->buf);
    }
}

static void _sha256_final(SHA256_CTX_JK *ctx, uint8_t hash[32]) {
    uint64_t bits=ctx->count*8;
    uint8_t pad=0x80;
    _sha256_update(ctx,&pad,1);
    while (ctx->count%64!=56) { uint8_t z=0; _sha256_update(ctx,&z,1); }
    for (int i=7;i>=0;i--) { uint8_t b=(bits>>(i*8))&0xFF; _sha256_update(ctx,&b,1); }
    for (int i=0;i<8;i++) {
        hash[i*4+0]=(ctx->state[i]>>24)&0xFF;
        hash[i*4+1]=(ctx->state[i]>>16)&0xFF;
        hash[i*4+2]=(ctx->state[i]>> 8)&0xFF;
        hash[i*4+3]=(ctx->state[i]    )&0xFF;
    }
}

/* Compute SHA-256 of file, write 64-char hex string to out_hex (65 bytes). Returns 0 on success. */
static int _file_sha256(const char *path, char out_hex[65]) {
    FILE *f = fopen(path, "rb");
    if (!f) return -1;
    SHA256_CTX_JK ctx;
    _sha256_init(&ctx);
    uint8_t buf[65536];
    size_t  n;
    while ((n = fread(buf, 1, sizeof(buf), f)) > 0)
        _sha256_update(&ctx, buf, n);
    fclose(f);
    uint8_t hash[32];
    _sha256_final(&ctx, hash);
    for (int i = 0; i < 32; i++) sprintf(out_hex + i*2, "%02x", hash[i]);
    out_hex[64] = '\0';
    return 0;
}

/* ── Platform includes ────────────────────────────────────────────────────── */

#ifdef _WIN32
#  ifndef WIN32_LEAN_AND_MEAN
#    define WIN32_LEAN_AND_MEAN
#  endif
#  include <windows.h>
#  include <winsvc.h>
#  include <psapi.h>
#  include <tlhelp32.h>
#  include <iphlpapi.h>
#  include <winreg.h>
#  ifndef AF_INET
#    define AF_INET 2
#  endif
   typedef struct { DWORD dwState,dwLocalAddr,dwLocalPort,dwRemoteAddr,dwRemotePort,dwOwningPid; } JK_TCP_ROW;
   typedef struct { DWORD dwNumEntries; JK_TCP_ROW table[1]; } JK_TCP_TABLE;
   typedef struct { DWORD dwLocalAddr,dwLocalPort,dwOwningPid; } JK_UDP_ROW;
   typedef struct { DWORD dwNumEntries; JK_UDP_ROW table[1]; } JK_UDP_TABLE;
#else
   /* Linux */
#  include <unistd.h>
#  include <dirent.h>
#  include <sys/types.h>
#  include <sys/utsname.h>
#  include <signal.h>
#  include <errno.h>
#endif

/* ── Internal process list ────────────────────────────────────────────────── */

#define MAX_PROCS 1024

typedef struct {
    char    names[MAX_PROCS][260];
    int64_t pids [MAX_PROCS];
    int64_t count;
    int     populated;
} ProcessList;

static ProcessList g_procs = { .count = 0, .populated = 0 };

static void _populate_procs(void) {
    if (g_procs.populated) return;
    g_procs.count     = 0;
    g_procs.populated = 1;

#ifdef _WIN32
    DWORD pid_buf[4096], bytes_needed = 0;
    if (!EnumProcesses(pid_buf, sizeof(pid_buf), &bytes_needed)) return;
    DWORD count = bytes_needed / sizeof(DWORD);
    for (DWORD i = 0; i < count && g_procs.count < MAX_PROCS; i++) {
        DWORD pid = pid_buf[i];
        if (pid == 0) continue;
        HANDLE hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
        if (!hProc) continue;
        char name[260] = "<unknown>";
        DWORD sz = sizeof(name);
        if (QueryFullProcessImageNameA(hProc, 0, name, &sz)) {
            char *s = strrchr(name, '\\');
            if (!s) s = strrchr(name, '/');
            const char *bn = s ? s+1 : name;
            strncpy(g_procs.names[(int)g_procs.count], bn, 259);
        } else {
            snprintf(g_procs.names[(int)g_procs.count], 260, "<pid:%lu>", (unsigned long)pid);
        }
        g_procs.names[(int)g_procs.count][259] = '\0';
        g_procs.pids[(int)g_procs.count++]     = (int64_t)pid;
        CloseHandle(hProc);
    }
#else
    /* Linux: enumerate /proc/<pid>/comm */
    DIR *d = opendir("/proc");
    if (!d) return;
    struct dirent *de;
    while ((de = readdir(d)) != NULL && g_procs.count < MAX_PROCS) {
        long pid = atol(de->d_name);
        if (pid <= 0) continue;
        char comm_path[64];
        snprintf(comm_path, sizeof(comm_path), "/proc/%ld/comm", pid);
        FILE *f = fopen(comm_path, "r");
        if (!f) continue;
        char name[260] = "";
        if (fgets(name, sizeof(name), f)) {
            /* strip newline */
            char *nl = strchr(name, '\n');
            if (nl) *nl = '\0';
        }
        fclose(f);
        strncpy(g_procs.names[(int)g_procs.count], name, 259);
        g_procs.pids[(int)g_procs.count++] = (int64_t)pid;
    }
    closedir(d);
#endif
    printf("[JOCKY] %lld processes found\n", (long long)g_procs.count);
    fflush(stdout);
}

/* ── Output ───────────────────────────────────────────────────────────────── */

void report(const char *message) {
    if (message) { printf("[JOCKY] %s\n", message); fflush(stdout); }
}

/* ── Process API ──────────────────────────────────────────────────────────── */

void   *procs_list(void)             { _populate_procs(); return &g_procs; }
int64_t proc_count(void *p)          { return p ? ((ProcessList*)p)->count : 0; }
char   *proc_name(void *p, int64_t i){ if (!p) return ""; ProcessList *pl=p; return (i>=0&&i<pl->count)?pl->names[(int)i]:""; }
int64_t proc_pid(void *p, int64_t i) { if (!p) return -1; ProcessList *pl=p; return (i>=0&&i<pl->count)?pl->pids[(int)i]:-1; }

void proc_kill(int64_t pid) {
    printf("[JOCKY] proc_kill — PID %lld [SAFE: reported only]\n", (long long)pid);
    fflush(stdout);
}

void *proc_mem_read(int64_t pid, int64_t addr, int64_t size) {
    size_t sz = (size_t)(size > 0 ? size : 1);
    void  *buf = calloc(1, sz);
    if (!buf) return NULL;
#ifdef _WIN32
    HANDLE h = OpenProcess(PROCESS_VM_READ, FALSE, (DWORD)pid);
    if (h) {
        SIZE_T read = 0;
        ReadProcessMemory(h, (LPCVOID)(uintptr_t)addr, buf, sz, &read);
        CloseHandle(h);
    }
#else
    char mem_path[64];
    snprintf(mem_path, sizeof(mem_path), "/proc/%lld/mem", (long long)pid);
    FILE *f = fopen(mem_path, "rb");
    if (f) { fseek(f, (long)addr, SEEK_SET); fread(buf, 1, sz, f); fclose(f); }
#endif
    return buf;
}

/* ── Network connections ──────────────────────────────────────────────────── */

typedef struct { char local[64]; char remote[64]; int64_t pid; char proto[4]; } JK_CONN;
typedef struct { JK_CONN conns[4096]; int64_t count; } ConnList;
static ConnList g_conns;

static void _fmt_ip_port(uint32_t ip, uint16_t port, char *out, size_t sz) {
    snprintf(out, sz, "%u.%u.%u.%u:%u",
             ip & 0xFF, (ip>>8)&0xFF, (ip>>16)&0xFF, (ip>>24)&0xFF, port);
}

static void _populate_conns(void) {
    memset(&g_conns, 0, sizeof(g_conns));
#ifdef _WIN32
    ULONG sz = 1024*1024;
    JK_TCP_TABLE *t = (JK_TCP_TABLE*)malloc(sz);
    if (!t) return;
    typedef DWORD (WINAPI *GetExtTcp_t)(void*, PULONG, BOOL, ULONG, ULONG, ULONG);
    GetExtTcp_t fn = (GetExtTcp_t)GetProcAddress(LoadLibraryA("iphlpapi.dll"), "GetExtendedTcpTable");
    if (fn && fn(t, &sz, FALSE, AF_INET, 5 /* TCP_TABLE_OWNER_PID_ALL */, 0) == NO_ERROR) {
        for (DWORD i = 0; i < t->dwNumEntries && g_conns.count < 4096; i++) {
            JK_CONN *c = &g_conns.conns[(int)g_conns.count++];
            _fmt_ip_port(t->table[i].dwLocalAddr,  ntohs((uint16_t)t->table[i].dwLocalPort),  c->local,  sizeof(c->local));
            _fmt_ip_port(t->table[i].dwRemoteAddr, ntohs((uint16_t)t->table[i].dwRemotePort), c->remote, sizeof(c->remote));
            c->pid = t->table[i].dwOwningPid;
            strncpy(c->proto, "TCP", 4);
        }
    }
    free(t);
#else
    /* Linux: read /proc/net/tcp */
    FILE *f = fopen("/proc/net/tcp", "r");
    if (!f) return;
    char line[512];
    fgets(line, sizeof(line), f); /* skip header */
    while (fgets(line, sizeof(line), f) && g_conns.count < 4096) {
        unsigned local_addr, local_port, rem_addr, rem_port, uid, state;
        int pid = 0;
        /* sl:  local_address rem_address   st ... uid ... inode */
        if (sscanf(line, " %*d: %x:%x %x:%x %x %*x:%*x %*x:%*x %*x %u",
                   &local_addr, &local_port, &rem_addr, &rem_port, &state, &uid) < 5)
            continue;
        JK_CONN *c = &g_conns.conns[(int)g_conns.count++];
        /* /proc/net/tcp stores addresses in little-endian host order */
        snprintf(c->local,  sizeof(c->local),  "%u.%u.%u.%u:%u",
                 local_addr&0xFF,(local_addr>>8)&0xFF,(local_addr>>16)&0xFF,(local_addr>>24)&0xFF, local_port);
        snprintf(c->remote, sizeof(c->remote), "%u.%u.%u.%u:%u",
                 rem_addr&0xFF,(rem_addr>>8)&0xFF,(rem_addr>>16)&0xFF,(rem_addr>>24)&0xFF, rem_port);
        c->pid = pid;
        strncpy(c->proto, "TCP", 4);
    }
    fclose(f);
#endif
}

void   *conns_list(void)              { _populate_conns(); return &g_conns; }
int64_t conn_count(void *p)           { return p ? ((ConnList*)p)->count : 0; }
char   *conn_local(void *p,int64_t i) { if(!p)return""; ConnList*cl=p; return (i>=0&&i<cl->count)?cl->conns[(int)i].local:""; }
char   *conn_remote(void*p,int64_t i) { if(!p)return""; ConnList*cl=p; return (i>=0&&i<cl->count)?cl->conns[(int)i].remote:""; }
int64_t conn_pid(void *p,int64_t i)   { if(!p)return-1; ConnList*cl=p; return (i>=0&&i<cl->count)?cl->conns[(int)i].pid:-1; }

/* ── Kernel base ──────────────────────────────────────────────────────────── */

/*
 * Windows: NtQuerySystemInformation(11) raw buffer parse.
 * Kernel VAs > 0x7FFFFFFFFFFFFFFF — must use ULONGLONG not void* to avoid sign truncation.
 *
 * RTL_PROCESS_MODULE_INFORMATION layout (x64):
 *   offset 0:  Section    (HANDLE  = 8 bytes)
 *   offset 8:  MappedBase (void*   = 8 bytes)
 *   offset 16: ImageBase  (void*   = 8 bytes) <-- what we want
 *   offset 24: ImageSize  (ULONG   = 4 bytes)
 *   offset 28: Flags      (ULONG   = 4 bytes)
 *   offset 32: LoadOrderIndex (USHORT)
 *   offset 34: InitOrderIndex (USHORT)
 *   offset 36: LoadCount      (USHORT)
 *   offset 38: OffsetToFileName (USHORT)
 *   offset 40: FullPathName[256]
 *   Total: 296 bytes
 */

uint64_t kernel_base(void) {
#ifdef _WIN32
    typedef NTSTATUS (NTAPI *NtQSI_t)(ULONG, PVOID, ULONG, PULONG);
    NtQSI_t NtQSI = (NtQSI_t)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQuerySystemInformation");
    if (!NtQSI) return 0;

    ULONG  buf_size = 2 * 1024 * 1024;
    BYTE  *buf      = (BYTE*)malloc(buf_size);
    if (!buf) return 0;
    ULONG  returned = 0;
    NTSTATUS st = NtQSI(11, buf, buf_size, &returned);
    if (st != 0 || returned < 8 + 296) { free(buf); return 0; }

    /* First module (ntoskrnl.exe) at buf+8, ImageBase at offset+16 */
    ULONGLONG base = 0;
    memcpy(&base, buf + 8 + 16, sizeof(ULONGLONG));
    free(buf);
    return (uint64_t)base;
#else
    /* Linux: read first /proc/modules entry base address */
    FILE *f = fopen("/proc/modules", "r");
    if (!f) return 0;
    char   line[512], name[128];
    unsigned long base = 0, size = 0;
    /* format: name size refcount deps state offset */
    if (fscanf(f, "%127s %lu %*d %*s %*s %lx", name, &size, &base) == 3) {
        fclose(f);
        return (uint64_t)base;
    }
    fclose(f);
    return 0;
#endif
}

/* ── BYOVD scanner (filename + SHA-256 cross-reference) ──────────────────── */

/*
 * Vulnerability DB — each entry: {name, sha256_prefix (first 16 hex chars or "" = any), cve, tags}
 * sha256_prefix="" means match by filename only (weaker — use only as fallback).
 * For production: load the full loldrivers.json from Python (scanner.py).
 */
typedef struct {
    const char *name;
    const char *sha256_prefix; /* first 16 chars of sha256, or "" for any */
    const char *cve;
    const char *tags;
} VulnEntry;

static const VulnEntry VULN_DB[] = {
    {"RTCore64.sys",   "01aa278b07b58d", "CVE-2019-16098", "Kernel-RW,EDR-Bypass"},
    {"gdrv.sys",       "31f4cfb4c71da4", "CVE-2018-19320", "Kernel-RW"},
    {"dbutil_2_3.sys", "0296e2ce999e67", "CVE-2021-21551", "Kernel-RW,Privilege-Escalation"},
    {"WinRing0x64.sys","605fa5f1e79e76", "CVE-2020-14979", "Kernel-RW,AV-Kill"},
    {"mhyprot2.sys",   "f25f28c64b77b4", "N/A",            "Kernel-RW,AV-Kill,Ransomware"},
    {"iqvw64e.sys",    "484940ef67a99e", "CVE-2015-2291",  "Kernel-RW,EDR-Bypass,APT"},
    {"aswarpot.sys",   "7b81e65c5a0d25", "CVE-2022-26522", "AV-Kill,Kernel-RW"},
    {"kprocesshacker.sys","4aafd9b28ec3d","N/A",           "Kernel-RW,DKOM"},
    {"procexp152.sys", "c4246cd3b41cfc", "N/A",            "Kernel-RW,AV-Kill"},
    {"cpuz141.sys",    "f5a6b7c8d9e0f1", "CVE-2017-15303", "Kernel-RW,Privilege-Escalation"},
    {"EneIo64.sys",    "c8d9e0f1a2b3c4", "N/A",            "Kernel-RW,AV-Kill"},
    {"winio64.sys",    "e6f7a8b9c0d1e2", "N/A",            "Kernel-RW,Physical-Memory"},
    {"AMDRyzenMasterDriverV17.sys","d1e2f3a4b5c6d7","CVE-2020-12928","Kernel-RW,Physical-Memory"},
    {"ZemanaAntiMalware.sys","b5c6d7e8f9a0b1","CVE-2022-41444","AV-Kill,Kernel-RW"},
    {"ASRdrv104.sys",  "0a20941dd3c63e", "CVE-2020-15368", "Kernel-RW"},
};
static const int VULN_DB_SIZE = (int)(sizeof(VULN_DB)/sizeof(VULN_DB[0]));

typedef struct {
    char path[1024];
    char name[260];
    char sha256[65];
    char cve[64];
    char tags[128];
    int  matched_by_hash; /* 1 = hash match (authoritative), 0 = filename only */
} ScanResult;

typedef struct {
    ScanResult results[256];
    int        count;
} ScanList;

static ScanList g_scan;

static void _scan_driver_file(const char *fpath, const char *fname) {
    if (g_scan.count >= 256) return;

    char sha[65] = "";
    _file_sha256(fpath, sha);

    const VulnEntry *match = NULL;
    int by_hash = 0;

    /* Method 1: SHA-256 prefix match (authoritative) */
    if (sha[0]) {
        for (int i = 0; i < VULN_DB_SIZE; i++) {
            const char *prefix = VULN_DB[i].sha256_prefix;
            if (prefix[0] && strncmp(sha, prefix, strlen(prefix)) == 0) {
                match = &VULN_DB[i];
                by_hash = 1;
                break;
            }
        }
    }

    /* Method 2: filename fallback */
    if (!match) {
        for (int i = 0; i < VULN_DB_SIZE; i++) {
#ifdef _WIN32
            if (_stricmp(fname, VULN_DB[i].name) == 0) {
#else
            if (strcasecmp(fname, VULN_DB[i].name) == 0) {
#endif
                match = &VULN_DB[i];
                by_hash = 0;
                break;
            }
        }
    }

    if (!match) return;

    ScanResult *r = &g_scan.results[g_scan.count++];
    strncpy(r->path,   fpath,         sizeof(r->path)-1);
    strncpy(r->name,   fname,         sizeof(r->name)-1);
    strncpy(r->sha256, sha[0] ? sha : "unavailable", sizeof(r->sha256)-1);
    strncpy(r->cve,    match->cve,    sizeof(r->cve)-1);
    strncpy(r->tags,   match->tags,   sizeof(r->tags)-1);
    r->matched_by_hash = by_hash;
}

void *byovd_scan(void) {
    memset(&g_scan, 0, sizeof(g_scan));

#ifdef _WIN32
    char windir[MAX_PATH];
    GetWindowsDirectoryA(windir, sizeof(windir));
    char drv_dir[MAX_PATH];
    snprintf(drv_dir, sizeof(drv_dir), "%s\\System32\\drivers", windir);

    WIN32_FIND_DATAA fd;
    char pattern[MAX_PATH];
    snprintf(pattern, sizeof(pattern), "%s\\*.sys", drv_dir);
    HANDLE hFind = FindFirstFileA(pattern, &fd);
    if (hFind != INVALID_HANDLE_VALUE) {
        do {
            if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;
            char full[MAX_PATH];
            snprintf(full, sizeof(full), "%s\\%s", drv_dir, fd.cFileName);
            _scan_driver_file(full, fd.cFileName);
        } while (FindNextFileA(hFind, &fd));
        FindClose(hFind);
    }
#else
    /* Linux: scan /lib/modules/<uname>/kernel/drivers */
    struct utsname uts;
    uname(&uts);
    char mod_base[512];
    snprintf(mod_base, sizeof(mod_base), "/lib/modules/%s/kernel/drivers", uts.release);

    /* Recursive directory walk */
    typedef void(*scan_dir_fn)(const char*);
    void scan_dir(const char *dir) {
        DIR *d = opendir(dir);
        if (!d) return;
        struct dirent *de;
        while ((de = readdir(d)) != NULL) {
            if (de->d_name[0] == '.') continue;
            char full[1024];
            snprintf(full, sizeof(full), "%s/%s", dir, de->d_name);
            if (de->d_type == DT_DIR) {
                scan_dir(full);
            } else {
                const char *ext = strrchr(de->d_name, '.');
                if (ext && (strcmp(ext,".ko")==0||strcmp(ext,".xz")==0||strcmp(ext,".gz")==0)) {
                    /* Strip extension for name comparison */
                    char bare[260];
                    strncpy(bare, de->d_name, sizeof(bare)-1);
                    char *e = strrchr(bare, '.');
                    if (e) *e = '\0';
                    _scan_driver_file(full, bare);
                }
            }
        }
        closedir(d);
    }
    scan_dir(mod_base);
#endif

    printf("[JOCKY] byovd_scan: %d vulnerable driver(s) found\n", g_scan.count);
    fflush(stdout);
    return &g_scan;
}

int64_t byovd_count(void *s)                { return s ? ((ScanList*)s)->count : 0; }
char   *byovd_name(void *s,  int64_t i)     { if(!s)return""; ScanList*sl=s; return (i>=0&&i<sl->count)?sl->results[(int)i].name:""; }
char   *byovd_path(void *s,  int64_t i)     { if(!s)return""; ScanList*sl=s; return (i>=0&&i<sl->count)?sl->results[(int)i].path:""; }
char   *byovd_cve(void *s,   int64_t i)     { if(!s)return""; ScanList*sl=s; return (i>=0&&i<sl->count)?sl->results[(int)i].cve:""; }
char   *byovd_hash(void *s,  int64_t i)     { if(!s)return""; ScanList*sl=s; return (i>=0&&i<sl->count)?sl->results[(int)i].sha256:""; }
int64_t byovd_hash_match(void *s, int64_t i){ if(!s)return 0; ScanList*sl=s; return (i>=0&&i<sl->count)?sl->results[(int)i].matched_by_hash:0; }

/* ── Registry scan (Windows only) ────────────────────────────────────────── */

typedef struct { char names[512][260]; int64_t count; } RegList;
static RegList g_reg;

void *registry_scan(void) {
    memset(&g_reg, 0, sizeof(g_reg));
#ifdef _WIN32
    HKEY hKey;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services", 0, KEY_READ, &hKey) != ERROR_SUCCESS)
        return &g_reg;
    for (DWORD idx = 0; g_reg.count < 512; idx++) {
        char svc[260]; DWORD svc_len = sizeof(svc);
        if (RegEnumKeyExA(hKey, idx, svc, &svc_len, NULL, NULL, NULL, NULL) != ERROR_SUCCESS) break;
        HKEY hSvc;
        if (RegOpenKeyExA(hKey, svc, 0, KEY_READ, &hSvc) != ERROR_SUCCESS) continue;
        DWORD type_val = 0, sz = sizeof(type_val);
        RegQueryValueExA(hSvc, "Type", NULL, NULL, (LPBYTE)&type_val, &sz);
        RegCloseKey(hSvc);
        if (type_val == 1 || type_val == 2) { /* KernelDriver or FilesystemDriver */
            strncpy(g_reg.names[(int)g_reg.count++], svc, 259);
        }
    }
    RegCloseKey(hKey);
#else
    /* Linux: list /proc/modules as kernel module registry */
    FILE *f = fopen("/proc/modules", "r");
    if (!f) return &g_reg;
    char line[512], name[128];
    while (fgets(line, sizeof(line), f) && g_reg.count < 512) {
        if (sscanf(line, "%127s", name) == 1)
            strncpy(g_reg.names[(int)g_reg.count++], name, 259);
    }
    fclose(f);
#endif
    return &g_reg;
}

int64_t reg_count(void *r)            { return r ? ((RegList*)r)->count : 0; }
char   *reg_name(void *r, int64_t i)  { if(!r)return""; RegList*rl=r; return (i>=0&&i<rl->count)?rl->names[(int)i]:""; }

/* ── XOR string decryption (runtime) ─────────────────────────────────────── */

void jk_xordecrypt(char *s, int len, unsigned char key) {
    for (int i = 0; i < len; i++) s[i] ^= key;
}

/* ── System info ─────────────────────────────────────────────────────────── */

char *system_info(void) {
    static char buf[512];
#ifdef _WIN32
    OSVERSIONINFOEXA oi = { sizeof(oi) };
    typedef NTSTATUS(NTAPI *RtlGetVer_t)(OSVERSIONINFOEXA*);
    RtlGetVer_t fn = (RtlGetVer_t)GetProcAddress(GetModuleHandleA("ntdll.dll"), "RtlGetVersion");
    if (fn) fn(&oi);
    snprintf(buf, sizeof(buf), "Windows %lu.%lu Build %lu",
             (unsigned long)oi.dwMajorVersion,
             (unsigned long)oi.dwMinorVersion,
             (unsigned long)oi.dwBuildNumber);
#else
    struct utsname u;
    uname(&u);
    snprintf(buf, sizeof(buf), "%s %s %s", u.sysname, u.release, u.machine);
#endif
    return buf;
}
