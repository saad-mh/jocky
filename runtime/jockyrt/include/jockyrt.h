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
#define JKF_ACCESS_RECORD_VERSION  1u
#define JKF_REGION_RECORD_VERSION  1u
#define JKF_MODULE_RECORD_VERSION  1u
#define JKF_THREAD_RECORD_VERSION  1u
#define JKF_DUMP_FORMAT_VERSION    1u
#define JKF_DUMP_ENTRY_VERSION     1u

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

/* ---- tool helpers (not a numbered requirement) --------------------- */

/* Packs this process's argv as NUL-separated UTF-8 into `buf` and returns the
 * argument count (argv[0] included). JKF_E_TOOSMALL if `buf` is short. Lets a
 * JOCKY `main` (which has no argv) parse a command line. */
int jkf_args(void *buf, uint64_t cap);

/* The main-image basename (UTF-8, e.g. "notepad.exe") of `pid`. Returns its
 * length (no NUL), JKF_E_NOTFOUND, or JKF_E_TOOSMALL. */
int jkf_process_name(uint32_t pid, void *buf, uint64_t cap);

/* The pid of the first process whose image basename case-insensitively equals
 * `name` (UTF-8), or JKF_E_NOTFOUND. */
int jkf_pid_by_name(const char *name);

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
#  define JKF_STATIC_ASSERT(c, m) _Static_assert(c, m)
#else
#  define JKF_STATIC_ASSERT(c, m)
#endif

JKF_STATIC_ASSERT(sizeof(JkfProcessRecord) == 20, "JkfProcessRecord layout");

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

/* ---- R.3  target open / close --------------------------------------- */

/* How much access jkf_open actually got. Layout: abi.md "JkfAccessRecord".
 * 16 bytes. */
typedef struct JkfAccessRecord {
    uint32_t version;      /* JKF_ACCESS_RECORD_VERSION */
    uint32_t level;        /* JKF_ACCESS_* */
    uint32_t grantedMask;  /* the Win32 PROCESS_* mask the open succeeded with */
    uint32_t reserved;     /* 0 */
} JkfAccessRecord;

JKF_STATIC_ASSERT(sizeof(JkfAccessRecord) == 16, "JkfAccessRecord layout");

enum {
    JKF_ACCESS_NONE       = 0,
    JKF_ACCESS_QUERY      = 1,  /* headers / regions only - reads will fail */
    JKF_ACCESS_READ       = 2,  /* query + VM read                          */
    JKF_ACCESS_READ_WRITE = 3   /* + VM write (test harness only)           */
};

/* Opens `pid` for inspection. `want_write` must be 0 in production; it is only
 * for the fixture harness. If `accessOut` is non-null (and `accessCap` >=
 * sizeof(JkfAccessRecord)) it receives a JkfAccessRecord describing the level
 * granted, so the scanner can record "queried headers only, could not read".
 *
 * Returns a positive handle-ish token for jkf_read / jkf_region_at / jkf_close,
 * or a negative JKF_E_*: JKF_E_ACCESS for a PPL / higher-integrity target,
 * JKF_E_NOTFOUND if the pid is gone. */
int jkf_open(uint32_t pid, int want_write, void *accessOut, uint64_t accessCap);

/* Closes a token from jkf_open. Returns JKF_OK, or JKF_E_BADHANDLE. */
int jkf_close(int handle);

/* ---- R.4  region walk ---------------------------------------------- */

/* Layout: abi.md "JkfRegionRecord". 48 bytes, 8-byte aligned. */
typedef struct JkfRegionRecord {
    uint32_t version;      /* JKF_REGION_RECORD_VERSION */
    uint32_t state;        /* MEM_COMMIT / MEM_RESERVE / MEM_FREE */
    uint32_t type;         /* MEM_IMAGE / MEM_MAPPED / MEM_PRIVATE; 0 if free */
    uint32_t protect;      /* PAGE_* now */
    uint32_t allocProtect; /* PAGE_* at reservation (0 if free) */
    uint32_t reserved;     /* 0 */
    uint64_t base;
    uint64_t size;
    uint64_t allocBase;    /* the reservation this region belongs to (0 if free) */
} JkfRegionRecord;

JKF_STATIC_ASSERT(sizeof(JkfRegionRecord) == 48, "JkfRegionRecord layout");

/* Writes one JkfRegionRecord for the region that contains `addr`, or the next
 * region after it. Returns 1 on a record, 0 at the end of the user address
 * space, or a negative JKF_E_*. The caller loops with `addr = base + size`. */
int jkf_region_at(int handle, uint64_t addr, void *out, uint64_t cap);

/* ---- R.5  read target memory ------------------------------------- */

/* Reads up to `len` bytes at `addr` into `buf`. Returns the number of bytes
 * actually read - which may be less than `len` for a partial read (a guard or
 * no-access page in the way) - or JKF_E_FAULT if nothing at `addr` is
 * readable. Internally chunked; never faults the caller. */
int jkf_read(int handle, uint64_t addr, void *buf, uint64_t len);

/* ---- R.6  module list -------------------------------------------- */

/* Layout: abi.md "JkfModuleRecord". 40 bytes, 8-byte aligned. `nameOff` /
 * `pathOff` are byte offsets into the `names` blob a jkf_modules() call fills
 * in parallel (each string UTF-8, NUL-terminated). */
typedef struct JkfModuleRecord {
    uint32_t version;      /* JKF_MODULE_RECORD_VERSION */
    uint32_t nameOff;      /* -> basename in the names blob    */
    uint32_t pathOff;      /* -> full path in the names blob   */
    uint32_t flags;        /* JKF_MOD_* */
    uint64_t base;
    uint64_t size;         /* SizeOfImage */
    uint64_t entryPoint;
} JkfModuleRecord;

JKF_STATIC_ASSERT(sizeof(JkfModuleRecord) == 40, "JkfModuleRecord layout");

enum { JKF_MOD_MAIN = 1u << 0 };  /* the process's own image */

/* Number of loader modules jkf_modules() would return. */
int jkf_module_count(int handle);

/* Fills `out` with JkfModuleRecord entries (ascending by base) and `names` with
 * the packed UTF-8 name/path blob they point into. Returns the module count, or
 * JKF_E_TOOSMALL if either buffer is short (nothing is written then; grow and
 * retry - 64 KiB of `names` covers a normal process). */
int jkf_modules(int handle, void *out, uint64_t outCap, void *names,
                uint64_t namesCap);

/* The backing file of the mapping that contains `addr` (for a region not in the
 * loader list). Writes a NUL-terminated UTF-8 path into `names` and returns its
 * length in bytes (excluding the NUL), JKF_E_NOTFOUND if `addr` is not
 * file-backed, or JKF_E_TOOSMALL. */
int jkf_mapped_name(int handle, uint64_t addr, void *names, uint64_t namesCap);

/* ---- R.7  thread enumeration --------------------------------------- */

/* Layout: abi.md "JkfThreadRecord". 32 bytes, 8-byte aligned. */
typedef struct JkfThreadRecord {
    uint32_t version;      /* JKF_THREAD_RECORD_VERSION */
    uint32_t tid;
    uint32_t flags;        /* reserved (0) */
    uint32_t reserved;     /* 0 */
    uint64_t startAddr;    /* Win32 start address (0 if it could not be read) */
    uint64_t teb;          /* TEB base (0 if it could not be read) */
} JkfThreadRecord;

JKF_STATIC_ASSERT(sizeof(JkfThreadRecord) == 32, "JkfThreadRecord layout");

/* Threads owned by `pid`. Takes a pid, not a jkf_open handle - it opens the
 * threads it needs itself. */
int jkf_thread_count(uint32_t pid);
int jkf_threads(uint32_t pid, void *out, uint64_t cap);

/* ---- R.9  dump container --------------------------------------------- */

/* On-disk layout (also spelled out in dump-format.md):
 *
 *   [ JkfDumpHeader ]                              at file offset 0
 *   repeated regionCount times:
 *     [ JkfDumpRegionEntry ] [ blobLen raw bytes ]
 *
 * A JOCKY scanner can reopen a dump offline and rebuild the region inventory
 * with the target gone. */

typedef struct JkfDumpHeader {
    char     magic[8];         /* "JKYDUMP\0" */
    uint32_t formatVersion;    /* JKF_DUMP_FORMAT_VERSION */
    uint32_t headerSize;       /* sizeof(JkfDumpHeader) == 128 */
    uint32_t targetPid;
    uint32_t regionCount;      /* filled in at jkf_dump_close */
    uint64_t timestamp;        /* Windows FILETIME (100ns ticks since 1601) */
    uint64_t totalBlobBytes;   /* filled in at jkf_dump_close */
    char     imageName[72];    /* target main-image basename, UTF-8, NUL-padded */
    uint8_t  reserved[16];     /* 0 */
} JkfDumpHeader;

JKF_STATIC_ASSERT(sizeof(JkfDumpHeader) == 128, "JkfDumpHeader layout");

typedef struct JkfDumpRegionEntry {
    uint32_t version;          /* JKF_DUMP_ENTRY_VERSION */
    uint32_t meta;             /* caller tag - e.g. F.2 per-region read status */
    uint64_t base;
    uint64_t size;             /* the region's full size */
    uint64_t blobLen;          /* raw bytes stored after this entry (0..size) */
} JkfDumpRegionEntry;

JKF_STATIC_ASSERT(sizeof(JkfDumpRegionEntry) == 32, "JkfDumpRegionEntry layout");

/* --- write side --- */

/* Creates `path` (UTF-8) and writes the header. `imageName` may be NULL.
 * Returns a positive dump-write token, or a negative JKF_E_*. */
int jkf_dump_open_write(const char *path, uint32_t targetPid,
                        const char *imageName);

/* Appends one region: a JkfDumpRegionEntry with `base` / `size` / `meta`,
 * followed by `len` bytes from `buf` (pass buf=NULL, len=0 for an unreadable
 * region - the entry is still recorded). Returns JKF_OK. */
int jkf_dump_put(int handle, uint64_t base, uint64_t size, uint32_t meta,
                 const void *buf, uint64_t len);

/* --- read side --- */

/* Opens an existing dump (UTF-8 path) and indexes it. Returns a positive
 * dump-read token. */
int jkf_dump_open_read(const char *path);

/* Copies the JkfDumpHeader into `out`. */
int jkf_dump_header(int handle, void *out, uint64_t cap);

int jkf_dump_region_count(int handle);

/* Copies region `index`'s JkfDumpRegionEntry into `out`. */
int jkf_dump_region(int handle, uint32_t index, void *out, uint64_t cap);

/* Copies region `index`'s stored bytes into `buf` and returns how many were
 * copied (min(blobLen, cap)). */
int jkf_dump_read(int handle, uint32_t index, void *buf, uint64_t cap);

/* Closes a read or write token from jkf_dump_open_*; for a write token this is
 * where regionCount / totalBlobBytes get patched into the header. */
int jkf_dump_close(int handle);

#ifdef __cplusplus
}  /* extern "C" */
#endif

#endif /* JOCKYRT_H */
