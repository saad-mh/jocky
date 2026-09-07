// Fixture for F.5.3: Executable mapped data (module stomping / section injection)
// Maps a data file as executable code.

#include <windows.h>
#include <stdio.h>
#include <string.h>

void inject_exec_mapped(const char *filepath) {
    // Open a file (could be any file, we'll use this fixture's own binary)
    HANDLE hFile = CreateFileA(filepath, GENERIC_READ, FILE_SHARE_READ, NULL,
                               OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        printf("CreateFile failed: %lu\n", GetLastError());
        return;
    }

    // Create a mapping from the file
    HANDLE hMapping = CreateFileMappingA(hFile, NULL, PAGE_WRITECOPY, 0, 0, NULL);
    if (!hMapping) {
        printf("CreateFileMapping failed\n");
        CloseHandle(hFile);
        return;
    }

    // Map with execute access (PAGE_EXECUTE_WRITECOPY simulates code execution over data)
    // Note: Windows may not allow PAGE_EXECUTE on a data file directly, so we use
    // VirtualAlloc + PAGE_EXECUTE_READ on the mapped memory as a workaround.
    LPVOID view = MapViewOfFile(hMapping, FILE_MAP_COPY, 0, 0, 4096);
    if (!view) {
        printf("MapViewOfFile failed\n");
        CloseHandle(hMapping);
        CloseHandle(hFile);
        return;
    }

    // Try to change protection to executable (this may fail on real data files)
    DWORD oldProt;
    VirtualProtect(view, 4096, PAGE_EXECUTE_READ, &oldProt);

    printf("Mapped file as executable at %p\n", view);
    Sleep(30000);  // Keep process alive for scanning

    UnmapViewOfFile(view);
    CloseHandle(hMapping);
    CloseHandle(hFile);
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("Usage: f5_3_exec_mapped.exe <filepath>\n");
        return 1;
    }

    inject_exec_mapped(argv[1]);
    return 0;
}
