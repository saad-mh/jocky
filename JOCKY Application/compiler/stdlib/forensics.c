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
#include "forensics.h"

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
