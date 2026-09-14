# BYOVD API Reference

## `DriverLoader` (`byovd/loader.py`)

Manages the full RTCore64.sys lifecycle: service installation, device handle, IOCTL dispatch, and teardown.

```python
from byovd.loader import DriverLoader
```

### Constructor

```python
DriverLoader(
    driver_path  : str  = "RTCore64.sys",
    service_name : str  = "RTCore64",
    device_name  : str  = r"\\.\RTCore64",
    simulate     : bool = False
)
```

- `simulate=True` makes all operations safe no-ops that print `[BYOVD/SIM]` and return plausible fake values. Use this for development and testing outside a VM.

### Methods

#### `load() -> bool`

Installs and starts the driver as a Windows service using `CreateServiceW` + `StartServiceW`. Requires `SeLoadDriverPrivilege` (Administrator).

Returns `True` on success, `False` on failure.

#### `open_device() -> bool`

Opens a device handle to `\\.\RTCore64` using `CreateFileW`. Must be called after `load()`.

Returns `True` on success.

#### `ioctl(code: int, in_buf: bytes) -> Optional[bytes]`

Issues a `DeviceIoControl` call with the given control code and input buffer.

IOCTL codes for RTCore64:
- `0x80002048` — kernel memory read
- `0x8000204C` — kernel memory write

Returns the output buffer bytes, or `None` on failure.

#### `unload()`

Stops and deletes the Windows service. Should be called in a `finally` block or via the context manager.

#### `check_privileges() -> bool` (static)

Returns `True` if the current process has Administrator privileges.

### Context Manager

```python
with DriverLoader(simulate=True) as loader:
    loader.open_device()
    data = loader.ioctl(0x80002048, my_buf)
```

`__exit__` calls `unload()` automatically.

---

## `KernelOps` (`byovd/kernel.py`)

Low-level kernel operations built on top of a `DriverLoader`.

```python
from byovd.kernel import KernelOps
```

### Constructor

```python
KernelOps(loader: DriverLoader)
```

### Memory Operations

#### `read_dword(addr: int) -> int`

Reads 4 bytes from kernel virtual address `addr`. Returns the value as an unsigned integer.

#### `read_qword(addr: int) -> int`

Reads 8 bytes from kernel virtual address `addr`. Returns the value as an unsigned integer.

#### `write_dword(addr: int, value: int)`

Writes a 32-bit value to kernel virtual address `addr`.

#### `write_qword(addr: int, value: int)`

Writes a 64-bit value to kernel virtual address `addr`.

### Kernel Base Resolution

#### `get_kernel_base() -> int`

Resolves the runtime virtual address of `ntoskrnl.exe`.

- **Method 1 (primary):** `NtQuerySystemInformation(SystemModuleInformation)` with raw buffer parsing. Correctly handles >63-bit kernel VAs (Windows uses the full 64-bit range for kernel space).
- **Method 2 (fallback):** `psapi.EnumDeviceDrivers`. Less reliable on some configurations.

Returns the base address as an integer, or a simulated value in simulation mode.

### Callback Enumeration

#### `find_psp_callback_table() -> int`

Locates `PspCreateProcessNotifyRoutine` (the kernel's process-notification callback array) at runtime.

**Method:** Reads `ntoskrnl.exe` from disk, parses its PE export table to find `PsSetCreateProcessNotifyRoutine`, then scans that function's prologue for `LEA R?X,[RIP+disp32]` instructions pointing to the callback table, and computes the runtime VA using the kernel base offset.

Returns the virtual address of the callback table, or `0` on failure.

#### `enum_process_callbacks(callback_table_addr: int) -> list[dict]`

Walks up to 64 8-byte slots in the callback table. For each non-null entry:

1. Masks the low 4 bits (Windows pointer encoding for callback entries).
2. Resolves which kernel module owns the address using `_get_module_map()`.
3. Calls `_is_microsoft_address()` to classify as Microsoft or non-Microsoft.

Returns a list of dicts:
```python
{
    "index":        int,   # slot index (0-63)
    "raw":          int,   # raw pointer value from the table slot
    "address":      int,   # address after masking low 4 bits
    "module":       str,   # owning kernel module name, or "unknown"
    "is_microsoft": bool   # True if the address is in a Microsoft-signed module
}
```

### Callback Patching

#### `patch_callback(table_addr: int, index: int) -> bool`

Nulls the callback entry at `table_addr + index * 8` using `write_qword`. Returns `True` on success.

#### `disable_non_microsoft_callbacks(table_addr: int) -> int`

Enumerates callbacks and patches all non-Microsoft entries. Returns the count of patched entries.

### EPROCESS Operations

#### `find_eprocess(pid: int, head_addr: int) -> int`

Walks the `EPROCESS` doubly-linked list starting from `head_addr` (pass `0` to use `PsInitialSystemProcess`) looking for a process with the given PID.

Returns the `EPROCESS` kernel address, or `0` if not found.

#### `steal_token(from_pid: int, to_pid: int, system_eprocess: int, target_eprocess: int) -> bool`

Copies the security token pointer from `from_pid`'s `EPROCESS` into `to_pid`'s `EPROCESS`. Used to grant SYSTEM-level privileges to an arbitrary process.

Returns `True` on success.

---

## `KernelInterface` (`byovd/kernel.py`)

High-level facade used by the TUI, CLI, and JIT stdlib. Manages the `DriverLoader` internally.

```python
from byovd.kernel import KernelInterface
```

### Constructor

```python
KernelInterface(simulate: bool = True)
```

Creates its own `DriverLoader`. If `simulate=False`, loads the real driver (requires Admin).

### Methods

#### `get_kernel_base() -> int`

Delegates to `KernelOps.get_kernel_base()`.

#### `enum_process_callbacks() -> list[dict]`

Calls `find_psp_callback_table()` then `enum_process_callbacks()`. Returns the same list format as `KernelOps.enum_process_callbacks()`.

#### `read_memory(addr: int, size: int) -> bytes`

Reads `size` bytes from kernel address `addr` in 8-byte chunks. Returns the bytes.

#### `write_memory(addr: int, data: bytes)`

Writes `data` to kernel address `addr` in 8-byte chunks.

#### `blind_callbacks(edr_cbs: list) -> int`

Takes a list of callback dicts (from `enum_process_callbacks`) and patches all entries marked `is_microsoft=False`. Returns the count of patched entries.

---

## `DriverScanner` (`byovd/scanner.py`)

Scans the local system's driver directories against the LOLDrivers database. Does not require Administrator or a loaded driver.

```python
from byovd.scanner import DriverScanner
```

### Constructor

```python
DriverScanner()
```

Loads `byovd/db/loldrivers.json` on init.

### Methods

#### `scan() -> list[dict]`

Walks Windows driver directories (`System32\drivers`, `SysWOW64\drivers`) or Linux `/lib/modules/`. For each `.sys` / `.ko` file:

1. Computes SHA-256 — compared against `KnownVulnerableSamples[].SHA256` (authoritative).
2. Filename match as fallback.

Returns a list of findings:
```python
{
    "path":  str,   # full path to the driver file
    "name":  str,   # filename
    "sha256": str,  # hex SHA-256 of the file
    "match": str,   # "sha256" or "filename"
    "entry": dict,  # full LOLDrivers DB entry
    "risk":  str,   # "CRITICAL" | "HIGH" | "MEDIUM" | "LOW"
    "score": int    # numeric risk score (0-10)
}
```

#### `db_entry_count() -> int`

Returns the number of entries in the loaded LOLDrivers database.

#### `print_report(findings: list[dict] = None)`

Prints a formatted report. If `findings` is `None`, calls `scan()` first.

### Risk Score Formula

```python
score = sum(tag_scores)   # per-tag values:
                          #   "Kernel-RW" -> 10
                          #   "AV-Kill"   -> 10
                          #   "EDR-Bypass"-> 9
                          #   "Kernel-Read"-> 7
                          #   others      -> 3-5

risk = "CRITICAL" if score >= 10 else
       "HIGH"     if score >= 7  else
       "MEDIUM"   if score >= 4  else
       "LOW"
```
