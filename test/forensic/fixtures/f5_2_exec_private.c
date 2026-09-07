// Fixture for F.5.2: Executable private memory (unbacked exec)
// Manually maps a DLL's sections into private memory without loader entry (reflective DLL).

#include <windows.h>
#include <stdio.h>

// For simplicity, this allocates an executable private region with some dummy code.
// A full reflective DLL loader would parse and map a real DLL, but detecting private
// executable memory is the key test here.

void inject_exec_private(void) {
    // Allocate private executable memory (no MEM_IMAGE, no loader list entry)
    LPVOID mem = VirtualAlloc(NULL, 4096, MEM_COMMIT, PAGE_EXECUTE_READ);
    if (!mem) {
        printf("VirtualAlloc failed\n");
        return;
    }

    // Write some dummy x64 code (NOP sled)
    memset(mem, 0x90, 4096);

    printf("Allocated private exec at %p\n", mem);
    Sleep(30000);  // Keep process alive for scanning

    VirtualFree(mem, 0, MEM_RELEASE);
}

int main(int argc, char *argv[]) {
    inject_exec_private();
    return 0;
}
