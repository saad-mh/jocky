/*
 * jockyrt - the JOCKY forensic runtime shim.
 *
 * A C static library that hides the Win32 / NT structs, handle lifetimes, and
 * Unicode paths behind a flat, JOCKY-friendly API. Linked into every forensic
 * build.
 *
 * THE FLAT ABI (requirement R.1)
 *
 *   - No C `struct` crosses the boundary as an argument or return value. Every
 *     jkf_* function takes only scalars and caller-owned byte buffers
 *     (`void* out` + a `uint64_t` capacity in bytes).
 *   - Records the shim writes into those buffers are fixed-size and
 *     fixed-layout, each led by a `uint32_t version`. The layouts are the
 *     `Jkf*Record` structs below and are also spelled out, field by field, in
 *     runtime/jockyrt/abi.md. A JOCKY program overlays its own struct on the
 *     bytes; the two must agree.
 *   - Return convention: `>= 0` is a count or a handle-ish token; `< 0` is
 *     `-(error code)` - one of the JKF_E_* values. When the code is JKF_E_OS,
 *     jkf_last_os_error() holds the GetLastError() captured at the failure.
 *
 * The shim only ever *reads* a target. It never writes target memory; the
 * `want_write` argument to jkf_open exists for the test harness alone.
 */

#ifndef JOCKYRT_H
#define JOCKYRT_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ---- versions ------------------------------------------------------------ */

/* Bumped when any record layout or function contract changes. */
#define JKF_ABI_VERSION 1u

#define JKF_PROCESS_RECORD_VERSION 1u
#define JKF_REGION_RECORD_VERSION  1u
#define JKF_MODULE_RECORD_VERSION  1u
#define JKF_THREAD_RECORD_VERSION  1u

uint32_t jkf_abi_version(void);

/* ---- error codes ------------------------------------------------------- */

enum {
    JKF_OK           = 0,
    JKF_E_INVAL      = -1,  /* a bad argument (null buffer, zero length, ...) */
    JKF_E_TOOSMALL   = -2,  /* caller buffer too small; ask the *_count call  */
    JKF_E_FAULT      = -3,  /* the whole address range is unreadable          */
    JKF_E_ACCESS     = -4,  /* access denied / insufficient privilege         */
    JKF_E_NOTFOUND   = -5,  /* no such pid / region / module / thread         */
    JKF_E_BADHANDLE  = -6,  /* not a handle this shim handed out              */
    JKF_E_OS         = -7,  /* an OS call failed; see jkf_last_os_error()     */
    JKF_E_NOMEM      = -8,
    JKF_E_UNSUPPORTED = -9  /* not available on this OS / build               */
};

/* The GetLastError() value captured when a jkf_* call last returned JKF_E_OS.
 * Thread-local. Meaningless unless the immediately preceding call failed with
 * JKF_E_OS. */
uint32_t jkf_last_os_error(void);

/* ---- R.2  process enumeration -------------------------------------- */

/* Layout: see abi.md "JkfProcessRecord". 20 bytes, 4-byte aligned. */
typedef struct JkfProcessRecord {
    uint32_t version;    /* JKF_PROCESS_RECORD_VERSION */
    uint32_t pid;
    uint32_t ppid;       /* parent pid (may name a since-exited process) */
    uint32_t sessionId;
    uint32_t flags;      /* JKF_PROC_* bitset */
} JkfProcessRecord;

#if defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L
_Static_assert(sizeof(JkfProcessRecord) == 20, "JkfProcessRecord layout");
#endif

enum {
    JKF_PROC_WOW64          = 1u << 0,  /* a 32-bit process on 64-bit Windows */
    JKF_PROC_PROTECTED      = 1u << 1,  /* a PPL / protected process          */
    JKF_PROC_ELEVATION_UNK  = 1u << 2   /* elevation was not determined       */
};

/* Number of processes the next jkf_processes() call would return. Never fails
 * for lack of buffer; may still return JKF_E_OS. */
int jkf_process_count(void);

/* Fills `out` with JkfProcessRecord entries, ascending by pid, and returns the
 * count. `cap` is `out`'s size in bytes. JKF_E_TOOSMALL if `cap` cannot hold
 * jkf_process_count() records. */
int jkf_processes(void *out, uint64_t cap);

/* ---- R.3  privilege ---------------------------------------------------- */

/* Tries to enable SeDebugPrivilege for the current process. Returns 1 if the
 * privilege is held afterwards, 0 if it is not (e.g. unelevated), or a negative
 * JKF_E_* on an OS failure. */
int jkf_enable_debug_privilege(void);

#ifdef __cplusplus
}  /* extern "C" */
#endif

#endif /* JOCKYRT_H */
