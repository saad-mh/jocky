# Evasion Toolkit — Overview

## Why User-Mode Evasion

EDR products operate in user-mode as well as kernel-mode. On the user-mode side, their primary visibility comes from:

1. **API hooks** — overwriting the first bytes of ntdll exports (e.g. `NtCreateProcess`) with a jump to the EDR's DLL so every syscall passes through their code.
2. **DLL injection visibility** — monitoring `LoadLibraryW` calls and the module list of every process.
3. **Process creation and thread events** — watching for new processes and their memory layouts.

The evasion module addresses each of these surfaces with a corresponding technique.

## What It Provides

Five independent modules, all Windows-only:

| Module | File | Technique |
|---|---|---|
| API unhooking | `evasion/api_unhook.py` | Restore hooked ntdll exports from clean disk copy |
| Direct syscalls | `evasion/syscall.py` | Issue NT syscalls without passing through ntdll hooks |
| DLL injection | `evasion/inject.py` | LoadLibrary inject + reflective DLL inject |
| Process hollowing | `evasion/hollow.py` | Replace a suspended process's image with a payload |
| Thread hijacking | `evasion/thread_hijack.py` | Redirect a running thread's RIP to shellcode |

All five modules are fully standalone — none imports from another. They are invoked independently by the TUI or directly via Python.

**Platform requirement:** All modules call `ctypes` against Win32 and ntdll APIs. On non-Windows they raise `ImportError` at import time.

## Techniques

### API Unhooking

EDR products install hooks by patching the first 5–15 bytes of ntdll functions with a `JMP` to their own monitoring DLL. The unhooker restores the original bytes by reading the clean ntdll.dll from disk (not the in-memory, already-hooked copy) and writing them back into the live process using `WriteProcessMemory`.

Use case: unhook before making sensitive API calls so they are not intercepted.

### Direct Syscalls

An alternative to unhooking. Instead of restoring ntdll's bytes, the direct-syscall module reads ntdll from disk, extracts the system call numbers (SSNs) for any `Nt` or `Zw` function, and builds minimal syscall stubs in RWX memory:

```asm
mov r10, rcx
mov eax, <SSN>
syscall
ret
```

The stub is returned as a callable ctypes function pointer. The call goes directly into the kernel without touching ntdll's in-memory bytes at all.

Use case: issue sensitive NT calls (e.g. `NtOpenProcess`, `NtAllocateVirtualMemory`) while bypassing all ntdll hooks entirely.

### DLL Injection

Two injection variants:

- **LoadLibrary inject** — Allocates memory in the target process, writes the DLL path as a UTF-16LE string, and creates a remote thread at `kernel32.LoadLibraryW`. Simple and widely understood; visible in the target's module list.
- **Reflective inject** — Finds the `ReflectiveDllMain` export in the DLL (a self-contained PE loader), writes the entire DLL into the target's memory, and creates a remote thread at the loader RVA. The DLL never goes through `LoadLibraryW` and does not appear in the normal module list.

### Process Hollowing

Creates a legitimate host process in suspended state (e.g. `svchost.exe`), unmaps its image using `NtUnmapViewOfSection`, then maps the payload PE into the same address space and transfers execution:

1. Reads the payload's preferred image base from its PE headers.
2. Attempts to allocate at the preferred base (falls back to any base).
3. Copies the payload's PE headers and all sections.
4. Applies base relocations (`IMAGE_REL_BASED_DIR64`) if the allocation differed from the preferred base.
5. Patches the PEB's `ImageBaseAddress` field so the process reports the correct image base.
6. Redirects the thread's RIP via `SetThreadContext` (CONTEXT offset `0xF8` on x64).
7. Resumes the thread.

The host process appears legitimate to process-listing tools. The payload runs under the host's PID and credentials.

### Thread Hijacking

Injects shellcode into a live process without creating a new thread:

1. Enumerates threads in the target via `CreateToolhelp32Snapshot`.
2. Suspends the chosen thread with `SuspendThread`.
3. Captures the thread's CPU context with `GetThreadContext`.
4. Allocates RWX memory in the target; writes the shellcode followed by a `push <original_rip>; ret` trampoline so the thread returns to its original position when the shellcode finishes.
5. Redirects the thread's RIP to the shellcode allocation.
6. Resumes with `ResumeThread`.

No new threads are created, which avoids thread-creation hooks.

## Source Files

| File | Role |
|---|---|
| `evasion/api_unhook.py` | `ApiUnhooker` class |
| `evasion/syscall.py` | `DirectSyscall` class |
| `evasion/inject.py` | `loadlibrary_inject`, `reflective_inject` functions |
| `evasion/hollow.py` | `hollow` function |
| `evasion/thread_hijack.py` | `hijack_thread`, `hijack_all_threads` functions |
| `evasion/__init__.py` | Package exports |
