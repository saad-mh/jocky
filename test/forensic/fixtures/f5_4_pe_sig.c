// Fixture for F.5.4: PE signature detection (reflective DLL / manual map)
// Writes a minimal PE header into private memory to test PE signature scanning.

#include <windows.h>
#include <stdio.h>
#include <string.h>

typedef struct {
    WORD e_magic;
    WORD e_unused[29];
    DWORD e_lfanew;
} PE_HEADER;

void inject_pe_signature(void) {
    // Allocate private memory
    LPVOID mem = VirtualAlloc(NULL, 4096, MEM_COMMIT, PAGE_READWRITE);
    if (!mem) {
        printf("VirtualAlloc failed\n");
        return;
    }

    // Write a minimal DOS header with MZ signature and valid e_lfanew
    PE_HEADER hdr;
    memset(&hdr, 0, sizeof(hdr));
    hdr.e_magic = 0x5A4D;     // "MZ"
    hdr.e_lfanew = 0x40;      // PE signature at offset 0x40

    memcpy(mem, &hdr, sizeof(hdr));

    // Write PE signature at offset 0x40: "PE\0\0"
    char *pePtr = (char *)mem + 0x40;
    pePtr[0] = 'P';
    pePtr[1] = 'E';
    pePtr[2] = 0;
    pePtr[3] = 0;

    // Fill rest with NOPs
    memset((char *)mem + sizeof(hdr), 0x90, 4096 - sizeof(hdr));

    printf("Wrote PE header at %p\n", mem);
    Sleep(30000);  // Keep process alive for scanning

    VirtualFree(mem, 0, MEM_RELEASE);
}

int main(int argc, char *argv[]) {
    inject_pe_signature();
    return 0;
}
