# Evasion API Reference

All modules are Windows-only. They raise `ImportError` on non-Windows at import time.

---

## `ApiUnhooker` (`evasion/api_unhook.py`)

Detects and removes EDR API hooks from in-memory DLL exports by comparing them against the clean on-disk copy.

```python
from evasion.api_unhook import ApiUnhooker
```

### Constructor

```python
ApiUnhooker(target_dll_path: str = r"C:\Windows\System32\ntdll.dll")
```

### Methods

#### `audit() -> list[dict]`

Compares the first 16 bytes of every export in the DLL:
- **Disk bytes:** read directly from the file at the export's RVA.
- **Memory bytes:** read from the in-process memory mapping via `ReadProcessMemory`.

A function is flagged as hooked if the memory bytes start with any of:
- `0xE9` / `0xEB` — `JMP rel32` / `JMP rel8` (most common EDR hook)
- `0x8B FF` — `MOV EDI, EDI` (Microsoft hotpatch placeholder, can be overwritten)
- `0xCC` — `INT3` (breakpoint hook)
- Push + `RET` pattern

Returns a list of flagged exports:
```python
{
    "function": str,    # export name
    "rva":      int,    # relative virtual address in the DLL
    "mem_addr": int,    # absolute VA in this process's memory
    "disk_bytes": bytes,  # first 16 bytes from disk
    "mem_bytes":  bytes   # first 16 bytes from memory (hooked)
}
```

#### `unhook(hooks: list[dict] = None) -> dict[str, bool]`

For each hook entry (or all if `hooks` is `None` and `audit()` has been called):
1. Calls `VirtualProtectEx` to make the target memory writable (PAGE_EXECUTE_READWRITE).
2. Calls `WriteProcessMemory` to overwrite the memory bytes with the original disk bytes.
3. Restores the original memory protection.

Returns `{function_name: success_bool}`.

#### `full_unhook()`

Convenience: calls `audit()` then `unhook()` on all detected hooks. Prints a summary.

### Example

```python
unhooker = ApiUnhooker(r"C:\Windows\System32\ntdll.dll")
hooks = unhooker.audit()
print(f"{len(hooks)} hooks detected")
unhooker.unhook(hooks)
```

---

## `DirectSyscall` (`evasion/syscall.py`)

Extracts NT system call numbers (SSNs) from on-disk ntdll.dll and builds callable direct-syscall stubs that bypass all in-memory hooks.

```python
from evasion.syscall import DirectSyscall
```

### Constructor

```python
DirectSyscall(dll_path: str = r"C:\Windows\System32\ntdll.dll")
```

### Methods

#### `get_ssn(func_name: str) -> Optional[int]`

Reads the function's stub bytes from disk and locates the `MOV EAX, imm32` (opcode `0xB8`) instruction that loads the system call number. Returns the SSN as an integer, or `None` if not found.

#### `get(func_name: str) -> Optional[ctypes.CFUNCTYPE]`

Returns a callable ctypes function pointer for the given NT function. The stub is:

```asm
mov r10, rcx    ; 49 89 CA
mov eax, <SSN>  ; B8 xx xx xx xx
syscall         ; 0F 05
ret             ; C3
```

Allocated in RWX memory. The returned callable uses the default C calling convention. You must supply the correct ctypes argument and return types for the specific function.

Returns `None` if the SSN cannot be extracted.

#### `dump_ssns(prefixes: tuple = ("Nt", "Zw")) -> dict[str, int]`

Enumerates all exports in ntdll whose name starts with any of the given prefixes and returns a `{name: ssn}` dictionary.

#### `print_ssn_table()`

Prints the full SSN table to stdout. Useful for auditing which syscalls are available.

### Example

```python
sc = DirectSyscall()
NtOpenProcess_fn = sc.get("NtOpenProcess")

# Set up ctypes prototype matching NtOpenProcess signature, then call:
# NtOpenProcess_fn(process_handle, access, obj_attr, client_id)
```

---

## `loadlibrary_inject` / `reflective_inject` (`evasion/inject.py`)

```python
from evasion.inject import loadlibrary_inject, reflective_inject
```

### `loadlibrary_inject(pid: int, dll_path: str) -> int`

Injects a DLL into process `pid` by:
1. Opening the process with `OpenProcess(PROCESS_ALL_ACCESS)`.
2. Allocating memory in the target for the DLL path string.
3. Writing the DLL path as a UTF-16LE null-terminated string.
4. Creating a remote thread at `kernel32.LoadLibraryW` with the DLL path pointer as argument.

Returns the remote thread handle (or `0` on failure).

The DLL will appear in the target process's module list via this method.

### `reflective_inject(pid: int, dll_path: str) -> int`

Injects a DLL into process `pid` without using `LoadLibraryW`:
1. Reads the DLL from disk.
2. Parses the DLL's export table to find the `ReflectiveDllMain` export (the self-loader).
3. Opens the target process and allocates memory equal to the DLL's size.
4. Writes the entire DLL bytes into the allocation.
5. Creates a remote thread at `remote_base + ReflectiveDllMain_RVA`.

The DLL's own reflective loader handles PE relocation and import resolution internally. The DLL does not appear via `GetModuleHandle` or in standard module enumeration.

Returns the remote thread handle (or `0` on failure).

**Requirement:** The target DLL must export a function named `ReflectiveDllMain`.

---

## `hollow` (`evasion/hollow.py`)

```python
from evasion.hollow import hollow
```

### `hollow(host_path: str, payload_path: str) -> int`

Replaces a newly-created host process's image with a payload PE.

1. Creates `host_path` as a suspended process (`CREATE_SUSPENDED`).
2. Uses `NtQueryInformationProcess(ProcessBasicInformation)` to get the PEB address.
3. Reads `PEB.ImageBaseAddress` at PEB offset `0x10`.
4. Calls `NtUnmapViewOfSection` to unmap the host image.
5. Reads the payload PE headers to get `OptionalHeader.ImageBase` (preferred base) and `SizeOfImage`.
6. Calls `VirtualAllocEx` at the preferred base (`MEM_COMMIT | MEM_RESERVE | PAGE_EXECUTE_READWRITE`). Falls back to any base if the preferred address is occupied.
7. Writes the payload's PE headers and all sections into the target.
8. If the actual allocation differs from the preferred base, applies `IMAGE_REL_BASED_DIR64` base relocations.
9. Writes the new image base into `PEB.ImageBaseAddress`.
10. Uses `SetThreadContext` to set the thread's RIP (CONTEXT offset `0xF8`) to `new_base + AddressOfEntryPoint`.
11. Calls `ResumeThread`.

Returns the PID of the hollowed process.

### Example

```python
pid = hollow(
    host_path    = r"C:\Windows\System32\svchost.exe",
    payload_path = r"C:\path\to\payload.exe"
)
print(f"Hollow process running as PID {pid}")
```

---

## `hijack_thread` / `hijack_all_threads` (`evasion/thread_hijack.py`)

```python
from evasion.thread_hijack import hijack_thread, hijack_all_threads
```

### `hijack_thread(pid: int, shellcode: bytes, tid: int = None) -> dict`

Redirects a thread in process `pid` to execute `shellcode`:

1. Enumerates threads using `CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD)`.
2. Selects the first thread belonging to `pid`, or `tid` if specified.
3. Opens the thread with `OpenThread(THREAD_ALL_ACCESS)`.
4. Calls `SuspendThread`.
5. Calls `GetThreadContext` to capture the current CONTEXT (including RIP).
6. Allocates RWX memory in the process.
7. Writes `shellcode` followed by a `push <original_rip>; ret` trampoline (10 bytes) so execution returns to the original RIP when the shellcode completes.
8. Updates CONTEXT.Rip to point at the shellcode allocation.
9. Calls `SetThreadContext` then `ResumeThread`.

Returns:
```python
{
    "tid":          int,   # thread ID that was hijacked
    "original_rip": int,   # RIP before hijack
    "new_rip":      int    # RIP after hijack (shellcode address)
}
```

### `hijack_all_threads(pid: int, shellcode: bytes) -> list[dict]`

Calls `hijack_thread` on every thread in the process. Returns a list of result dicts, one per thread.
