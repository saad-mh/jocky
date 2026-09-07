// Fixture for F.5.7: Thread start address anomaly
// Creates a thread with a start address that points outside any module.

#include <windows.h>
#include <stdio.h>

// A simple thread function (won't actually run, just needs to exist)
DWORD WINAPI dummy_thread(LPVOID param) {
    Sleep(1000);
    return 0;
}

void create_anomalous_thread(void) {
    // Allocate private memory for a fake thread start address
    LPVOID fakeStart = VirtualAlloc(NULL, 4096, MEM_COMMIT, PAGE_EXECUTE_READ);
    if (!fakeStart) {
        printf("VirtualAlloc failed\n");
        return;
    }

    // Write some dummy code
    memset(fakeStart, 0x90, 4096);

    // Create a thread that will start at this fake address
    // Note: This thread will crash when it tries to execute, but that's okay for testing.
    // The forensic scanner will see the thread's start address pointing to private exec memory.
    HANDLE hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)fakeStart, NULL, 0, NULL);
    if (!hThread) {
        printf("CreateThread failed: %lu\n", GetLastError());
        VirtualFree(fakeStart, 0, MEM_RELEASE);
        return;
    }

    printf("Created thread with anomalous start address at %p\n", fakeStart);
    Sleep(30000);  // Keep process alive for scanning

    WaitForSingleObject(hThread, 1000);
    CloseHandle(hThread);
    VirtualFree(fakeStart, 0, MEM_RELEASE);
}

int main(int argc, char *argv[]) {
    create_anomalous_thread();
    return 0;
}
