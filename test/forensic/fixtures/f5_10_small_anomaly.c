// Fixture for F.5.10: Small anomalies (single-page executable, code cave)
// Allocates a single-page executable region to test detection of small anomalies.

#include <windows.h>
#include <stdio.h>

void inject_single_page_exec(void) {
    // Allocate exactly one page (4096 bytes) of executable memory
    LPVOID mem = VirtualAlloc(NULL, 4096, MEM_COMMIT, PAGE_EXECUTE_READ);
    if (!mem) {
        printf("VirtualAlloc failed\n");
        return;
    }

    // Write some dummy code
    memset(mem, 0x90, 4096);

    printf("Allocated single-page exec at %p\n", mem);
    Sleep(30000);  // Keep process alive for scanning

    VirtualFree(mem, 0, MEM_RELEASE);
}

int main(int argc, char *argv[]) {
    inject_single_page_exec();
    return 0;
}
