#include "jockyrt.h"

#include "jockyrt_internal.h"

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(_WIN32)
#  define WIN32_LEAN_AND_MEAN
#  include <windows.h>
#  define jkf_fseek64 _fseeki64
#else
#  define jkf_fseek64 fseeko
#endif

/* Dump tokens are their own namespace (not the jkf_open handle table). */
enum { JKF_DUMP_SLOTS = 16 };

typedef struct {
    FILE *fp;
    int reading;               /* 1 = read token, 0 = write token */
    uint32_t count;
    uint64_t totalBlob;
    JkfDumpHeader hdr;          /* read side: the parsed header */
    JkfDumpRegionEntry *entries;  /* read side: count entries */
    uint64_t *blobOffsets;        /* read side: file offset of each blob */
} DumpSlot;

static DumpSlot g_dumps[JKF_DUMP_SLOTS];

static int slot_alloc(void) {
    for (int i = 1; i < JKF_DUMP_SLOTS; ++i)
        if (g_dumps[i].fp == NULL) return i;
    return JKF_E_NOMEM;
}

static DumpSlot *slot_get(int token) {
    if (token <= 0 || token >= JKF_DUMP_SLOTS || g_dumps[token].fp == NULL)
        return NULL;
    return &g_dumps[token];
}

static FILE *open_utf8(const char *path, const wchar_t *wmode,
                       const char *amode) {
#if defined(_WIN32)
    wchar_t wpath[1024];
    if (MultiByteToWideChar(CP_UTF8, 0, path, -1, wpath, 1024) <= 0) return NULL;
    return _wfopen(wpath, wmode);
#else
    return fopen(path, amode);
#endif
}

static uint64_t now_filetime(void) {
#if defined(_WIN32)
    FILETIME ft;
    GetSystemTimeAsFileTime(&ft);
    return ((uint64_t)ft.dwHighDateTime << 32) | ft.dwLowDateTime;
#else
    return 0;
#endif
}

/* ---- write side ---------------------------------------------------- */

int jkf_dump_open_write(const char *path, uint32_t targetPid,
                        const char *imageName) {
    if (!path) return JKF_E_INVAL;
    const int token = slot_alloc();
    if (token < 0) return token;

    FILE *fp = open_utf8(path, L"wb", "wb");
    if (!fp) return JKF_E_OS;

    DumpSlot *s = &g_dumps[token];
    memset(s, 0, sizeof *s);
    s->fp = fp;

    JkfDumpHeader h;
    memset(&h, 0, sizeof h);
    memcpy(h.magic, "JKYDUMP", 7);  /* byte 7 stays NUL */
    h.formatVersion = JKF_DUMP_FORMAT_VERSION;
    h.headerSize = (uint32_t)sizeof(JkfDumpHeader);
    h.targetPid = targetPid;
    h.timestamp = now_filetime();
    if (imageName)
        strncpy(h.imageName, imageName, sizeof h.imageName - 1);

    if (fwrite(&h, sizeof h, 1, fp) != 1) {
        fclose(fp);
        s->fp = NULL;
        return JKF_E_OS;
    }
    return token;
}

int jkf_dump_put(int handle, uint64_t base, uint64_t size, uint32_t meta,
                 const void *buf, uint64_t len) {
    DumpSlot *s = slot_get(handle);
    if (!s || s->reading) return JKF_E_BADHANDLE;
    if (len && !buf) return JKF_E_INVAL;

    JkfDumpRegionEntry e;
    e.version = JKF_DUMP_ENTRY_VERSION;
    e.meta = meta;
    e.base = base;
    e.size = size;
    e.blobLen = len;
    if (fwrite(&e, sizeof e, 1, s->fp) != 1) return JKF_E_OS;
    if (len && fwrite(buf, 1, (size_t)len, s->fp) != (size_t)len)
        return JKF_E_OS;

    s->count += 1;
    s->totalBlob += len;
    return JKF_OK;
}

static int close_write(DumpSlot *s) {
    int rc = JKF_OK;
    if (fseek(s->fp, (long)offsetof(JkfDumpHeader, regionCount), SEEK_SET) != 0 ||
        fwrite(&s->count, sizeof s->count, 1, s->fp) != 1)
        rc = JKF_E_OS;
    if (fseek(s->fp, (long)offsetof(JkfDumpHeader, totalBlobBytes), SEEK_SET) !=
            0 ||
        fwrite(&s->totalBlob, sizeof s->totalBlob, 1, s->fp) != 1)
        rc = JKF_E_OS;
    fclose(s->fp);
    s->fp = NULL;
    return rc;
}

/* ---- read side -------------------------------------------------- */

static void free_index(DumpSlot *s) {
    free(s->entries);
    s->entries = NULL;
    free(s->blobOffsets);
    s->blobOffsets = NULL;
}

int jkf_dump_open_read(const char *path) {
    if (!path) return JKF_E_INVAL;
    const int token = slot_alloc();
    if (token < 0) return token;

    FILE *fp = open_utf8(path, L"rb", "rb");
    if (!fp) return JKF_E_OS;

    DumpSlot *s = &g_dumps[token];
    memset(s, 0, sizeof *s);
    s->fp = fp;
    s->reading = 1;

    if (fread(&s->hdr, sizeof s->hdr, 1, fp) != 1 ||
        memcmp(s->hdr.magic, "JKYDUMP", 7) != 0 ||
        s->hdr.formatVersion != JKF_DUMP_FORMAT_VERSION) {
        fclose(fp);
        s->fp = NULL;
        return JKF_E_INVAL;
    }

    const uint32_t n = s->hdr.regionCount;
    s->count = n;
    if (n) {
        s->entries = calloc(n, sizeof(JkfDumpRegionEntry));
        s->blobOffsets = calloc(n, sizeof(uint64_t));
        if (!s->entries || !s->blobOffsets) {
            free_index(s);
            fclose(fp);
            s->fp = NULL;
            return JKF_E_NOMEM;
        }
    }

    int64_t pos = (int64_t)sizeof(JkfDumpHeader);
    for (uint32_t i = 0; i < n; ++i) {
        if (jkf_fseek64(fp, pos, SEEK_SET) != 0 ||
            fread(&s->entries[i], sizeof(JkfDumpRegionEntry), 1, fp) != 1) {
            free_index(s);
            fclose(fp);
            s->fp = NULL;
            return JKF_E_INVAL;
        }
        pos += (int64_t)sizeof(JkfDumpRegionEntry);
        s->blobOffsets[i] = (uint64_t)pos;
        pos += (int64_t)s->entries[i].blobLen;
    }
    return token;
}

int jkf_dump_header(int handle, void *out, uint64_t cap) {
    DumpSlot *s = slot_get(handle);
    if (!s || !s->reading) return JKF_E_BADHANDLE;
    if (!out || cap < sizeof(JkfDumpHeader)) return JKF_E_INVAL;
    memcpy(out, &s->hdr, sizeof s->hdr);
    return JKF_OK;
}

int jkf_dump_region_count(int handle) {
    DumpSlot *s = slot_get(handle);
    if (!s || !s->reading) return JKF_E_BADHANDLE;
    return (int)s->count;
}

int jkf_dump_region(int handle, uint32_t index, void *out, uint64_t cap) {
    DumpSlot *s = slot_get(handle);
    if (!s || !s->reading) return JKF_E_BADHANDLE;
    if (index >= s->count) return JKF_E_NOTFOUND;
    if (!out || cap < sizeof(JkfDumpRegionEntry)) return JKF_E_INVAL;
    memcpy(out, &s->entries[index], sizeof(JkfDumpRegionEntry));
    return JKF_OK;
}

int jkf_dump_read(int handle, uint32_t index, void *buf, uint64_t cap) {
    DumpSlot *s = slot_get(handle);
    if (!s || !s->reading) return JKF_E_BADHANDLE;
    if (index >= s->count) return JKF_E_NOTFOUND;
    if (!buf) return JKF_E_INVAL;

    uint64_t want = s->entries[index].blobLen;
    if (want > cap) want = cap;
    if (want > 0x7fffffffull) want = 0x7fffffffull;
    if (want == 0) return 0;
    if (jkf_fseek64(s->fp, (int64_t)s->blobOffsets[index], SEEK_SET) != 0)
        return JKF_E_OS;
    return (int)fread(buf, 1, (size_t)want, s->fp);
}

int jkf_dump_close(int handle) {
    DumpSlot *s = slot_get(handle);
    if (!s) return JKF_E_BADHANDLE;
    int rc;
    if (!s->reading) {
        rc = close_write(s);
    } else {
        fclose(s->fp);
        s->fp = NULL;
        rc = JKF_OK;
    }
    free_index(s);
    return rc;
}
