// Fixture for F.5.1: RWX and write-then-exec detection
// Allocates RWX memory and writes shellcode, or allocates RW then changes to RX.

#include <windows.h>
#include <stdio.h>

// Technique 1: Allocate directly as RWX and write
void inject_rwx(void) {
    LPVOID mem = VirtualAlloc(NULL, 4096, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (!mem) {
        printf("VirtualAlloc failed\n");
        return;
    }

    // Write a NOP sled (0x90 repeated)
    memset(mem, 0x90, 4096);

    printf("Allocated RWX at %p\n", mem);
    Sleep(30000);  // Keep process alive for scanning

    VirtualFree(mem, 0, MEM_RELEASE);
}

// Technique 2: Allocate RW, write, then change to RX
void inject_write_then_exec(void) {
    LPVOID mem = VirtualAlloc(NULL, 4096, MEM_COMMIT, PAGE_READWRITE);
    if (!mem) {
        printf("VirtualAlloc failed\n");
        return;
    }

    // Write a NOP sled
    memset(mem, 0x90, 4096);

    // Change protection to RX
    DWORD oldProt;
    if (!VirtualProtect(mem, 4096, PAGE_EXECUTE_READ, &oldProt)) {
        printf("VirtualProtect failed\n");
        return;
    }

    printf("Allocated RW->RX at %p\n", mem);
    Sleep(30000);  // Keep process alive for scanning

    VirtualFree(mem, 0, MEM_RELEASE);
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("Usage: f5_1_rwx.exe <rwx|write-exec>\n");
        return 1;
    }

    if (strcmp(argv[1], "rwx") == 0) {
        inject_rwx();
    } else if (strcmp(argv[1], "write-exec") == 0) {
        inject_write_then_exec();
    } else {
        printf("Unknown technique: %s\n", argv[1]);
        return 1;
    }

    return 0;
}
