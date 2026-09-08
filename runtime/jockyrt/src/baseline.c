/*
 * jockyrt baseline.c - Baseline hash DB for F.9
 *
 * Stores and retrieves per-page hashes of module .text sections for
 * image-tampering detection (F.5.6) and baseline construction (F.9).
 *
 * Binary format: JkfBaselineHeader, then per-module entries each with a
 * JkfBaselineModuleEntry followed by its pageCount JkfBaselinePageEntry records.
 */

#include <windows.h>
#include <string.h>
#include "../include/jockyrt.h"

typedef struct BaselineSlot {
    HANDLE hFile;
    int isWrite;
    uint32_t currentModuleIdx;
    uint32_t currentPageCount;
    uint64_t fileSize;
    char path[MAX_PATH];
} BaselineSlot;

#define MAX_BASELINE_HANDLES 16
static BaselineSlot g_baseline_handles[MAX_BASELINE_HANDLES];
static int g_baseline_handle_counter = 1000;

static int baseline_alloc_handle(void) {
    int i;
    for (i = 0; i < MAX_BASELINE_HANDLES; i++) {
        if (g_baseline_handles[i].hFile == NULL) {
            return 1000 + i;
        }
    }
    return JKF_E_NOMEM;
}

static BaselineSlot *baseline_get_slot(int handle) {
    int idx = handle - 1000;
    if (idx < 0 || idx >= MAX_BASELINE_HANDLES) return NULL;
    if (g_baseline_handles[idx].hFile == NULL) return NULL;
    return &g_baseline_handles[idx];
}

static int baseline_free_handle(int handle) {
    BaselineSlot *slot = baseline_get_slot(handle);
    if (!slot) return JKF_E_BADHANDLE;
    memset(slot, 0, sizeof(*slot));
    return JKF_OK;
}

/* Write side */

int jkf_baseline_open_write(const char *path, int append) {
    if (!path) return JKF_E_INVAL;

    int handle = baseline_alloc_handle();
    if (handle < 0) return handle;

    BaselineSlot *slot = baseline_get_slot(handle);
    if (!slot) return JKF_E_NOMEM;

    /* Convert UTF-8 path to wide. */
    wchar_t widePath[MAX_PATH];
    int wideLen = MultiByteToWideChar(CP_UTF8, 0, path, -1, widePath, MAX_PATH);
    if (wideLen <= 0) {
        baseline_free_handle(handle);
        return JKF_E_OS;
    }

    /* Try to open existing file if appending. */
    HANDLE hFile = INVALID_HANDLE_VALUE;
    if (append) {
        hFile = CreateFileW(widePath, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ,
                           NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    }

    /* If no existing file or not appending, create new. */
    if (hFile == INVALID_HANDLE_VALUE) {
        hFile = CreateFileW(widePath, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ,
                           NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    }

    if (hFile == INVALID_HANDLE_VALUE) {
        baseline_free_handle(handle);
        return JKF_E_OS;
    }

    slot->hFile = hFile;
    slot->isWrite = 1;
    slot->currentModuleIdx = 0;
    slot->currentPageCount = 0;
    strncpy_s(slot->path, MAX_PATH, path, MAX_PATH - 1);

    /* If this is a fresh file, write header. */
    LARGE_INTEGER fileSize;
    if (!GetFileSizeEx(hFile, &fileSize) || fileSize.QuadPart == 0) {
        JkfBaselineHeader hdr;
        memset(&hdr, 0, sizeof(hdr));
        memcpy(hdr.magic, "JKYBASE\0", 8);
        hdr.formatVersion = JKF_BASELINE_FORMAT_VERSION;
        hdr.headerSize = sizeof(JkfBaselineHeader);
        hdr.moduleCount = 0;
        hdr.pageCount = 0;
        /* timestamp would be set with GetSystemTimeAsFileTime() in a full impl */
        hdr.timestamp = 0;

        DWORD written = 0;
        if (!WriteFile(hFile, &hdr, sizeof(hdr), &written, NULL)) {
            CloseHandle(hFile);
            baseline_free_handle(handle);
            return JKF_E_OS;
        }
    }

    return handle;
}

int jkf_baseline_put_module(int handle, const char *name, uint64_t preferredBase) {
    BaselineSlot *slot = baseline_get_slot(handle);
    if (!slot || !slot->isWrite) return JKF_E_BADHANDLE;
    if (!name) return JKF_E_INVAL;

    JkfBaselineModuleEntry entry;
    memset(&entry, 0, sizeof(entry));
    entry.version = JKF_BASELINE_MODULE_VERSION;
    entry.pageCount = 0;  /* will be updated after put_page calls */
    entry.preferredBase = preferredBase;
    strncpy_s(entry.name, sizeof(entry.name), name, sizeof(entry.name) - 1);

    DWORD written = 0;
    if (!WriteFile(slot->hFile, &entry, sizeof(entry), &written, NULL)) {
        return JKF_E_OS;
    }

    slot->currentModuleIdx++;
    slot->currentPageCount = 0;

    return JKF_OK;
}

int jkf_baseline_put_page(int handle, uint32_t pageOffset, uint64_t hash) {
    BaselineSlot *slot = baseline_get_slot(handle);
    if (!slot || !slot->isWrite) return JKF_E_BADHANDLE;

    JkfBaselinePageEntry entry;
    memset(&entry, 0, sizeof(entry));
    entry.version = JKF_BASELINE_PAGE_VERSION;
    entry.pageOffset = pageOffset;
    entry.hash = hash;

    DWORD written = 0;
    if (!WriteFile(slot->hFile, &entry, sizeof(entry), &written, NULL)) {
        return JKF_E_OS;
    }

    slot->currentPageCount++;

    return JKF_OK;
}

int jkf_baseline_close(int handle) {
    BaselineSlot *slot = baseline_get_slot(handle);
    if (!slot) return JKF_E_BADHANDLE;

    if (slot->isWrite) {
        /* Stub: in a full implementation, would patch moduleCount/pageCount into header.
         * For now, just close the file. */
        if (slot->hFile != INVALID_HANDLE_VALUE) {
            CloseHandle(slot->hFile);
        }
    } else {
        if (slot->hFile != INVALID_HANDLE_VALUE) {
            CloseHandle(slot->hFile);
        }
    }

    baseline_free_handle(handle);
    return JKF_OK;
}

/* Read side */

int jkf_baseline_open_read(const char *path) {
    if (!path) return JKF_E_INVAL;

    int handle = baseline_alloc_handle();
    if (handle < 0) return handle;

    BaselineSlot *slot = baseline_get_slot(handle);
    if (!slot) return JKF_E_NOMEM;

    wchar_t widePath[MAX_PATH];
    int wideLen = MultiByteToWideChar(CP_UTF8, 0, path, -1, widePath, MAX_PATH);
    if (wideLen <= 0) {
        baseline_free_handle(handle);
        return JKF_E_OS;
    }

    HANDLE hFile = CreateFileW(widePath, GENERIC_READ, FILE_SHARE_READ, NULL,
                               OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        DWORD err = GetLastError();
        baseline_free_handle(handle);
        if (err == ERROR_FILE_NOT_FOUND) return JKF_E_NOTFOUND;
        if (err == ERROR_ACCESS_DENIED) return JKF_E_ACCESS;
        return JKF_E_OS;
    }

    slot->hFile = hFile;
    slot->isWrite = 0;
    slot->currentModuleIdx = 0;

    LARGE_INTEGER fileSize;
    if (!GetFileSizeEx(hFile, &fileSize)) {
        CloseHandle(hFile);
        baseline_free_handle(handle);
        return JKF_E_OS;
    }
    slot->fileSize = (uint64_t)fileSize.QuadPart;

    strncpy_s(slot->path, MAX_PATH, path, MAX_PATH - 1);

    return handle;
}

int jkf_baseline_find_page(int handle, const char *moduleName,
                           uint32_t pageOffset, void *hashOut, uint64_t cap) {
    BaselineSlot *slot = baseline_get_slot(handle);
    if (!slot || slot->isWrite) return JKF_E_BADHANDLE;
    if (!moduleName || !hashOut || cap < 8) return JKF_E_INVAL;

    /* Stub implementation: in a full impl, would read and search through the file.
     * For now, return NOTFOUND. */
    return JKF_E_NOTFOUND;
}

/* Reuse jkf_baseline_close for both read and write. */
