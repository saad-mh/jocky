/*
 * jockyrt file.c - File I/O for F.5.6 / F.9
 *
 * Provides jkf_file_size and jkf_file_read for reading on-disk module files
 * to support baseline hash DB (F.9) and image-tampering detection (F.5.6).
 */

#include <windows.h>
#include "../include/jockyrt.h"

/* Get the file size by opening and querying via GetFileSize.
 * Returns size or a negative error code. */
int jkf_file_size(const char *path) {
    if (!path) return JKF_E_INVAL;

    /* Convert UTF-8 path to wide for Windows API. */
    wchar_t widePath[MAX_PATH];
    int wideLen = MultiByteToWideChar(CP_UTF8, 0, path, -1, widePath, MAX_PATH);
    if (wideLen <= 0) return JKF_E_OS;

    HANDLE hFile = CreateFileW(widePath, GENERIC_READ, FILE_SHARE_READ, NULL,
                               OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        DWORD err = GetLastError();
        if (err == ERROR_FILE_NOT_FOUND) return JKF_E_NOTFOUND;
        if (err == ERROR_ACCESS_DENIED) return JKF_E_ACCESS;
        return JKF_E_OS;
    }

    LARGE_INTEGER fileSize;
    BOOL ok = GetFileSizeEx(hFile, &fileSize);
    CloseHandle(hFile);

    if (!ok) return JKF_E_OS;
    if (fileSize.QuadPart > INT_MAX) return JKF_E_OS;  /* too large */

    return (int)fileSize.QuadPart;
}

/* Read up to len bytes from offset in path into buf.
 * Returns bytes read, or a negative error code. */
int jkf_file_read(const char *path, uint64_t offset, void *buf, uint64_t len) {
    if (!path || !buf || len == 0) return JKF_E_INVAL;
    if (len > (uint64_t)INT_MAX) return JKF_E_INVAL;

    wchar_t widePath[MAX_PATH];
    int wideLen = MultiByteToWideChar(CP_UTF8, 0, path, -1, widePath, MAX_PATH);
    if (wideLen <= 0) return JKF_E_OS;

    HANDLE hFile = CreateFileW(widePath, GENERIC_READ, FILE_SHARE_READ, NULL,
                               OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        DWORD err = GetLastError();
        if (err == ERROR_FILE_NOT_FOUND) return JKF_E_NOTFOUND;
        if (err == ERROR_ACCESS_DENIED) return JKF_E_ACCESS;
        return JKF_E_OS;
    }

    /* Seek to offset. */
    LARGE_INTEGER seekPos;
    seekPos.QuadPart = (LONGLONG)offset;
    if (!SetFilePointerEx(hFile, seekPos, NULL, FILE_BEGIN)) {
        CloseHandle(hFile);
        return JKF_E_OS;
    }

    /* Read. */
    DWORD bytesRead = 0;
    BOOL ok = ReadFile(hFile, buf, (DWORD)len, &bytesRead, NULL);
    CloseHandle(hFile);

    if (!ok) return JKF_E_OS;

    return (int)bytesRead;
}
