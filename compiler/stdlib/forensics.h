/*
 * forensics.h — JOCKY Standard Library: Public API
 *
 * This header declares all functions available to JOCKY programs.
 * Compiled by gcc into forensics.o and linked with the JOCKY output object.
 *
 * Type mapping (JOCKY → C):
 *   num     → int64_t   (64-bit signed integer)
 *   dec     → double
 *   text    → char*     (null-terminated string)
 *   flag    → int64_t   (0 = no, 1 = yes)
 *   raw     → void*     (opaque pointer — caller must not dereference)
 *   nothing → void
 */

#ifndef JOCKY_FORENSICS_H
#define JOCKY_FORENSICS_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ── Output ────────────────────────────────────────────────────────────────── */
void    report         (const char* message);

/* ── Process enumeration ───────────────────────────────────────────────────── */
void*   procs_list     (void);
int64_t proc_count     (void* procs);
char*   proc_name      (void* procs, int64_t index);
int64_t proc_pid       (void* procs, int64_t index);
void    proc_kill      (int64_t pid);
void*   proc_mem_read  (int64_t pid, int64_t addr, int64_t size);

/* ── Network ───────────────────────────────────────────────────────────────── */
void*   net_conns      (void);
void*   net_sniff      (int64_t duration_ms);

/* ── Registry ──────────────────────────────────────────────────────────────── */
char*   reg_read       (const char* key, const char* value_name);
void*   reg_list       (const char* key);

/* ── File system ───────────────────────────────────────────────────────────── */
void*   file_list      (const char* path);
void*   file_read      (const char* path);

/* ── System ────────────────────────────────────────────────────────────────── */
void*   sys_info       (void);
void*   hash_file      (const char* path);

/* ── Runtime string decryptor ──────────────────────────────────────────────── */
char*   jk_xordecrypt  (const char* enc, int64_t n);

/* ── BYOVD: driver scanner ─────────────────────────────────────────────────── */
void*   byovd_scan             (void);
int64_t byovd_driver_count     (void* scan_result);
char*   byovd_driver_name      (void* scan_result, int64_t index);
char*   byovd_driver_path      (void* scan_result, int64_t index);
char*   byovd_driver_cve       (void* scan_result, int64_t index);
char*   byovd_driver_risk      (void* scan_result, int64_t index);

/* ── BYOVD: driver loader ──────────────────────────────────────────────────── */
int64_t byovd_load             (const char* driver_path);
void    byovd_unload           (void);

/* ── BYOVD: kernel operations ─────────────────────────────────────────────── */
void*   kernel_read            (int64_t address, int64_t size);
void    kernel_write           (int64_t address, int64_t value);
int64_t kernel_base            (void);
void*   kernel_enum_callbacks  (void);
int64_t kernel_callback_count  (void* cb_list);
int64_t kernel_callback_addr   (void* cb_list, int64_t index);
char*   kernel_callback_module (void* cb_list, int64_t index);
int64_t kernel_patch_callback  (int64_t index);
int64_t kernel_blind_edr       (void);

#ifdef __cplusplus
}
#endif

#endif /* JOCKY_FORENSICS_H */
