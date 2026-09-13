# JOCKY Framework — Codebase Reference

Every file in the framework explained: what it does, why it exists, and the key functions inside it.

---

## Root

### `jocky_terminal.py`

The main entry point. A Rich-powered TUI that exposes every framework capability through numbered menus. Run `python jocky_terminal.py` to start.

Key functions:
- `menu()` — generic numbered menu display
- `menu_scripts()` — list pre-built .jk scripts; selecting one opens the 9-option action submenu
- `_script_action_menu(script_path, script_name)` — per-script submenu with nine actions
- `_run_jit(script_path, script_name, obfuscate)` — compile + JIT-execute (optionally with obfuscation passes)
- `_run_kernel_mode(script_path, script_name)` — set `JOCKY_KERNEL_MODE=1` env var then JIT-execute
- `_build_native_binary(script_path, script_name)` — compile to native `.exe` via gcc/MinGW
- `_view_script_source(script_path, script_name)` — display source with Rich syntax highlighting
- `_show_script_tokens(script_path, script_name)` — lex and display first 80 tokens
- `_show_script_ast(script_path, script_name)` — parse and display function names + statement counts
- `_show_script_ir(script_path, script_name)` — run full pipeline and show first 5000 chars of LLVM IR
- `_show_pipeline_summary(script_path, script_name)` — run compile with `emit_ir=True` for a full summary
- `menu_editor()` — interactive code editor for scratch.jk
- `menu_inspector()` — inspect lexer tokens, AST, LLVM IR
- `menu_build()` — compile .jk to native exe
- `menu_byovd()` — BYOVD scanner, kernel base, callbacks, blind
- `menu_evasion()` — API unhooking, syscalls, hollowing, injection, thread hijacking
- `menu_c2()` — start server, connect agent, configure domain fronting
- `menu_langref()` — inline language reference
- `main()` — dispatch loop

---

### `jocky.py`

Thin CLI wrapper. Parses command-line arguments and delegates to `compiler.py`. Lets you run `python jocky.py source.jk --run` without needing to `cd compiler/`.

---

### `jocky.bat` / `jocky.sh`

OS-level launchers. `jocky.bat` sets up the PATH for MinGW on Windows, then calls `python jocky.py`. `jocky.sh` does the equivalent on Linux/macOS.

---

### `setup.bat` / `setup.sh`

First-run setup scripts. Install Python dependencies (`pip install -r requirements.txt`), and on Windows also attempt to locate or download MinGW gcc for native compilation.

---

### `requirements.txt`

Python package dependencies:
- `llvmlite` — LLVM Python bindings (IR building, MCJIT, object emission)
- `rich` — TUI rendering (panels, tables, syntax highlighting)

---

## `compiler/`

### `compiler/compiler.py`

The top-level compilation pipeline orchestrator.

Key functions:
- `compile_jocky()` — runs all 5 stages: Lexer → Parser → Semantic → CodeGen → Obfuscation
- `_run_jit()` — JIT-executes using MCJIT, registers Python stdlib callbacks
- `_emit_and_link()` — emits .o, generates per-build import variation shim, links with gcc
- `_generate_import_variation_shim()` — randomly picks 4–12 decoy imports from 30 Windows functions; writes a C shim that imports them so every exe has a different import table hash
- `_minimal_shim()` — fallback shim if variation shim fails to compile

---

### `compiler/jocky/lexer.py`

Tokenises `.jk` source text into a stream of `Token` objects. Handles:
- Keywords (`func`, `let`, `if`, `else`, `for`, `while`, `return`)
- Literals (integers, hex integers, strings, booleans)
- Operators and punctuation
- Identifiers
- Line tracking for error reporting

---

### `compiler/jocky/parser.py`

Recursive-descent parser. Builds an AST from the token stream.

AST node types:
- `Program` — top-level list of function definitions
- `FunctionDef` — name, params, body
- `LetStmt` — variable declaration
- `AssignStmt` — variable assignment
- `IfStmt` — condition, true branch, optional else branch
- `ForStmt` — init, condition, increment, body
- `WhileStmt` — condition, body
- `CallStmt` / `CallExpr` — function call
- `BinaryExpr` — arithmetic/comparison/logical operation
- `UnaryExpr` — logical NOT, negation
- `IntLit`, `StrLit`, `BoolLit` — literal values
- `VarRef` — variable reference

Raises `ParseError` on syntax violations.

---

### `compiler/jocky/semantic.py`

Type-checks the AST. Enforces:
- All variables declared before use
- Type consistency in binary expressions (no int + string)
- Function call argument types match declaration
- No redeclaration of variables in same scope

Raises `SemanticError` with line number and description.

---

### `compiler/jocky/codegen.py`

Generates LLVM IR from the checked AST using `llvmlite.ir`.

Key responsibilities:
- Creates an `ir.Module` with all JOCKY functions as `ir.Function`
- Declares all stdlib functions as external (`ir.Function` with external linkage)
- Compiles each statement to LLVM IR instructions
- Handles string allocation (global `ir.Constant` arrays)
- Maps JOCKY types to LLVM types: `int` → `i64`, `string` → `i8*`, `bool` → `i1`, `proc/conn/mem` → `i8*`
- Raises `CodegenError` on unresolvable expressions

---

### `compiler/jocky/passes.py`

Applies obfuscation to the LLVM IR module after CodeGen.

Key functions:
- `ObfuscationPasses.run_all()` — runs all four passes in sequence
- `_inject_build_id()` — adds `_jk_build_id` global with 16 random bytes
- `_encrypt_strings()` — XOR-encrypts all string globals, inserts decrypt calls
- `_inject_entropy()` — adds `_jk_entropy` 64-bit random global
- `_inject_dead_code()` — creates companion functions with opaque predicates
- `compute_hash(path)` — SHA-256 of a file (used to show polymorphism)

---

### `compiler/jocky/stdlib.py`

Python implementations of all JOCKY stdlib functions, used in JIT mode. When MCJIT executes, it resolves extern function calls by looking them up in the Python process's symbol table via `ctypes.CFUNCTYPE`.

Key registrations (via `register_all()`):

**Output**
- `report` → Python `print` (prefixed `[JOCKY]`)

**Process**
- `procs_list`, `proc_count`, `proc_name`, `proc_pid`, `proc_kill`, `proc_mem_read` → process enumeration via ctypes/psutil; Linux falls back to `/proc`

**Network**
- `net_conns` → prints TCP table, returns sentinel handle
- `net_sniff(duration_ms)` → shows ESTABLISHED connections for given duration

**Registry** (Windows only)
- `reg_read(key_path, value_name)` → `winreg.OpenKey(HKEY_LOCAL_MACHINE, key) + QueryValueEx`; returns string value
- `reg_list(key_path)` → `winreg.EnumKey` to enumerate subkeys; returns sentinel handle

**File system**
- `file_list(path)` → `os.listdir(path)`; returns sentinel handle
- `file_read(path)` → reads up to 65536 bytes as string

**System**
- `sys_info` → platform string via `platform.platform()`
- `hash_file(path)` → SHA-256 hex digest via `hashlib`

**BYOVD / Driver scanner**
- `byovd_scan` → calls `DriverScanner().scan()`, caches result; returns sentinel handle
- `byovd_driver_count` → `len(scan_results)`
- `byovd_driver_name(handle, idx)` → `findings[idx]['name']`
- `byovd_driver_path(handle, idx)` → `findings[idx]['path']`
- `byovd_driver_cve(handle, idx)` → `findings[idx].get('entry',{}).get('CVE','N/A')`
- `byovd_driver_risk(handle, idx)` → `findings[idx].get('risk','UNKNOWN')`
- `byovd_load` → simulation log
- `byovd_unload` → simulation log

**Kernel (via KernelInterface)**
- `kernel_base` → `KernelInterface(simulate=True).get_kernel_base()`
- `kernel_read(addr, size)` → `ki.read_memory(addr, size)`; returns buffer pointer
- `kernel_write(addr, data)` → `ki.write_memory(addr, data)`
- `kernel_enum_callbacks` → `ki.enum_process_callbacks()`; caches result; returns sentinel
- `kernel_callback_count` → `len(callbacks)`
- `kernel_callback_addr(handle, idx)` → `cbs[idx]['address'] & 0x7FFFFFFFFFFFFFFF`
- `kernel_callback_module(handle, idx)` → `cbs[idx].get('module','unknown')`
- `kernel_patch_callback(addr)` → simulation log
- `kernel_blind_edr` → filters non-Microsoft callbacks and logs each patched

**Obfuscation support**
- `jk_xordecrypt` → XOR decryption stub (used internally by obfuscation pass 2)

---

### `compiler/stdlib/forensics.c`

Native C implementations of the same stdlib functions, linked into native `.exe` builds. This is the file that runs on target machines — no Python dependency.

Key sections:
- **SHA-256** — self-contained implementation (no openssl), used for `byovd_scan` hash cross-reference
- **Process list** — Windows: `EnumProcesses` + `QueryFullProcessImageNameA`; Linux: `/proc/<pid>/comm`
- **Network connections** — Windows: `GetExtendedTcpTable`; Linux: `/proc/net/tcp` parsing
- **`kernel_base()`** — Windows: raw `NtQuerySystemInformation(11)` buffer parse, reads `ImageBase` as `ULONGLONG` (fixes the `c_void_p` sign truncation bug); Linux: `/proc/modules`
- **`byovd_scan()`** — scans driver directories, computes SHA-256 of each file, cross-references against embedded vulnerability table (both hash prefix and filename fallback), returns `ScanList`
- **`registry_scan()`** — Windows: `HKLM\SYSTEM\CurrentControlSet\Services` Type=1/2; Linux: `/proc/modules`
- **`jk_xordecrypt()`** — XOR decryption for obfuscated string literals at runtime
- **`system_info()`** — Windows: `RtlGetVersion`; Linux: `uname()`

### `compiler/stdlib/forensics.h`

Header file declaring all C function signatures used by the JOCKY compiler. Included by both `forensics.c` and, conceptually, by the generated entry shim.

---

## `byovd/`

### `byovd/kernel.py`

The `KernelInterface` class — the core of the BYOVD engine.

Key methods:
- `get_kernel_base()` — two-method resolution:
  1. `NtQuerySystemInformation(11)` with raw bytes buffer + `struct.unpack_from('<Q', buf, 8+16)` (avoids ctypes `c_void_p` sign truncation)
  2. `psapi!EnumDeviceDrivers` with `ctypes.c_uint64` array fallback
- `_is_microsoft_address(addr)` — builds module map, checks `[base, base+size)` containment, then checks module name against `_MICROSOFT_MODULES` whitelist (30+ names including ntoskrnl, tcpip.sys, ntfs.sys, etc.)
- `_get_module_map()` — parses NtQuerySystemInformation(11) result into `[{base, size, name}]` list; sim mode returns realistic fake map including MsMpEng.sys, CSFalcon.sys, SentinelOne.sys
- `enum_process_callbacks()` — PE scan of ntoskrnl.exe on disk to find `PspCreateProcessNotifyRoutine`, reads entries via RTCore64, classifies each by module
- `read_memory(addr, size)` — RTCore64 IOCTL 0x80002048 kernel read
- `write_memory(addr, data)` — RTCore64 IOCTL 0x8000204C kernel write
- `blind_callbacks(cbs)` — null non-Microsoft callback pointers via kernel write
- Simulation mode (`simulate=True`) — all operations return realistic fake data; no kernel access attempted

---

### `byovd/loader.py`

The `DriverLoader` class — loads/unloads signed vulnerable drivers.

Key methods:
- `load()` — on Windows with admin: `CreateServiceW`, `StartServiceW`, `OpenSCManagerW`; simulation mode: returns True without touching kernel
- `unload()` — `StopService`, `DeleteService`
- `open_device(path)` — `CreateFileW` to `\\.\RTCore64` (or other device name)
- `ioctl(code, in_buf, out_buf)` — `DeviceIoControl` wrapper

---

### `byovd/scanner.py`

The `DriverScanner` class — scans the system for vulnerable drivers using the LOLDrivers database.

Key methods:
- `_load_db()` — loads `byovd/db/loldrivers.json`
- `_build_indices()` — builds `{name_lower: entry}` and `{sha256_lower: entry}` indices for O(1) lookup
- `scan()` — dispatches to `_scan_windows()` or `_scan_linux()` based on platform
- `_scan_windows()` — walks `System32\drivers` and `SysWOW64\drivers`, SHA-256 each .sys, cross-references hash first, filename second
- `_scan_linux()` — walks `/lib/modules/<uname>/kernel/drivers`, handles .ko/.ko.xz/.ko.gz
- `_risk_score(entry)` — scores 1–10 based on tags (Kernel-RW=10, AV-Kill=10, Ransomware=8, etc.)
- `print_report()` — formatted scan results

---

### `byovd/db/loldrivers.json`

JSON array of 40+ vulnerable driver entries. Each entry:
```json
{
  "Name": "RTCore64.sys",
  "Vendor": "ASUS/MSI",
  "CVE": "CVE-2019-16098",
  "Tags": ["Kernel-RW", "EDR-Bypass", "AV-Kill"],
  "Description": "...",
  "DeviceName": "\\\\.\\RTCore64",
  "KnownVulnerableSamples": [
    {"SHA256": "01aa278b..."}
  ]
}
```

Covers: RTCore64, gdrv, dbutil_2_3, WinRing0x64, mhyprot2, iqvw64e, LenovoDiagnosticsDriver, aswarpot, procexp152, cpuz141, AMDRyzenMasterDriverV17, ZemanaAntiMalware, and 30+ more.

---

## `evasion/`

### `evasion/api_unhook.py`

Detects and removes EDR hooks in ntdll.dll (or any DLL) by comparing on-disk bytes vs in-memory bytes for every exported function.

Key functions:
- `_get_exports(pe_bytes)` — parses PE export table, returns `{name: RVA}`
- `_is_hooked(bytes)` — detects jmp hooks (0xE9, 0xFF, 0xEB, 0xE8), hotpatch (0x8B 0xFF), INT3, push+ret
- `ApiUnhooker.audit()` — compare disk vs memory for each export, collect hooked functions
- `ApiUnhooker.unhook(hooks)` — `VirtualProtectEx(RWX)` + `WriteProcessMemory` to restore original bytes
- `ApiUnhooker.full_unhook()` — audit then unhook all detected hooks

---

### `evasion/syscall.py`

Extracts System Service Numbers (SSNs) from on-disk ntdll.dll and builds direct syscall stubs in executable memory, bypassing any hooks placed in the ntdll in-memory copy.

Key functions:
- `_extract_ssn_from_disk(func_name)` — reads ntdll.dll from disk, finds function RVA in export table, scans stub for `MOV EAX, imm32` (opcode 0xB8), extracts SSN
- `_build_syscall_stub(ssn)` — returns 10-byte stub: `mov r10,rcx / mov eax,ssn / syscall / ret`
- `_alloc_exec(data)` — `VirtualAlloc(RWX)` + copy stub
- `DirectSyscall.get(func_name)` — returns callable `ctypes.CFUNCTYPE` for named syscall
- `DirectSyscall.dump_ssns()` — parse all Nt*/Zw* exports and return full SSN table

---

### `evasion/inject.py`

Two DLL injection methods.

Key functions:
- `loadlibrary_inject(pid, dll_path)` — classic: write path to remote process, `CreateRemoteThread(LoadLibraryW)`
- `_find_reflective_loader_rva(dll_bytes)` — parse PE exports to find `ReflectiveDllMain`
- `reflective_inject(pid, dll_path)` — write full DLL to remote process as `PAGE_EXECUTE_READWRITE`, find `ReflectiveDllMain` export, `CreateRemoteThread` at loader RVA

---

### `evasion/hollow.py`

Process hollowing — create a sacrificial host process in suspended state, rip out its executable image, map a replacement PE, fix relocations, and resume at the new entry point.

Key functions:
- `hollow(host_path, payload_path)` — full hollowing pipeline
- `_pe_headers(data)` — parse NT headers: image base, entry RVA, image size, section count
- `_get_sections(data, h)` — parse section table
- `_get_peb_image_base_addr(hproc, hthread)` — `NtQueryInformationProcess` → `PEB.ImageBaseAddress` at offset 0x10
- `_set_rip(hproc, hthread, rip)` — `GetThreadContext` + patch Rip at offset 0xF8 + `SetThreadContext`
- `_apply_relocations()` — walk IMAGE_BASE_RELOCATION blocks, apply `IMAGE_REL_BASED_DIR64` fixups

---

### `evasion/thread_hijack.py`

Suspend a thread in a target process, redirect its instruction pointer to shellcode, resume. The shellcode ends with a trampoline that jumps back to the original RIP.

Key functions:
- `_enum_threads(pid)` — `CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD)` + `Thread32First/Next`
- `_get_context(hthread)` → raw `CONTEXT` buffer (1232 bytes, CONTEXT_ALL = 0x10001F)
- `_get_rip(ctx)` / `_set_rip(ctx, rip)` — read/write Rip at offset 0xF8
- `hijack_thread(pid, shellcode, tid)` — suspend, capture context, alloc+write shellcode+trampoline, redirect Rip, resume
- `hijack_all_threads(pid, shellcode)` — hijack every thread in process

---

## `c2/`

### `c2/server.py`

Asyncio-based C2 server that accepts multiple simultaneous agent connections.

Key classes/functions:
- `AgentSession` — per-agent connection state: sid, reader/writer, pending futures, info dict
- `AgentSession.exec_script(path)` — send CMD, await RESULT future (with timeout)
- `AgentSession.exec_code(code)` — send JOCKY source, await execution result
- `C2Server.start()` — `asyncio.start_server()` on configured host:port (optional TLS)
- `C2Server._handle_client()` — handshake, message loop, deliver results to pending futures
- `C2Server.list_agents()` — enumerate connected agents with uptime/idle info
- `C2Server.exec_all(code)` — broadcast to all agents concurrently with `asyncio.gather`
- `C2Server.interactive_loop()` — management shell (list, exec, execall, quit)

---

### `c2/agent.py`

The agent runs on target endpoints. Connects to the C2 server, receives commands, executes JOCKY scripts locally, reports results.

Key functions:
- `_collect_info()` — hostname, platform, arch, PID, username
- `_exec_script(path)` — import and run `JockyCompiler.run_file()`
- `_exec_code(code)` — write to temp .jk file, compile and run
- `C2Agent.run()` — connect, HELLO handshake, message loop with auto-reconnect
- `C2Agent._handle_cmd()` — dispatch exec_script / exec_code / shell
- `C2Agent._ping_loop()` — send PING every 30s to keep connection alive

---

### `c2/fronting.py`

Domain fronting transport and SOCKS5 proxy client.

Key classes/functions:
- `socks5_connect(proxy_host, proxy_port, dest_host, dest_port)` — full SOCKS5 handshake (method negotiation, auth, CONNECT request), returns `(reader, writer)` connected to dest via proxy
- `FrontedTransport` — HTTP(S) transport with domain fronting
  - `post(payload)` — HTTP POST, `Host: <real C2>` header (encrypted in TLS), TCP connects to `<CDN front>`
  - `get(params)` — HTTP GET equivalent
  - Supports optional SOCKS5 proxy as first hop
- `FrontedBeacon` — periodic check-in via `FrontedTransport.post()`, calls `on_command` callback on server response

---

## `scripts/`

Pre-built `.jk` scripts demonstrating framework capabilities:

| File | Purpose |
|------|---------|
| `byovd_scanner.jk` | Scan system drivers against LOLDrivers DB — reports CVE, risk, path |
| `kernel_recon.jk` | Kernel base + callback enumeration + EDR detection + blind operation |
| `proc_scanner.jk` | Enumerate all running processes with threat classification |
| `resource_monitor.jk` | Detect resource-abusing malware (miners, worms, RATs) via process scan |
| `threat_hunter.jk` | Full-spectrum hunt: processes + network + registry + file checks |
| `registry_inspector.jk` | Inspect persistence keys, Winlogon, Defender policy, LSA protection |
| `sys_info.jk` | System triage: process categories, registry build info, network snapshot |
| `net_monitor.jk` | Network connection snapshot cross-referenced with process list |
| `net_logger.jk` | Repeated network + process snapshots building a monitoring timeline |
| `packet_sniffer.jk` | Passive packet capture with sniffer/tunneling process correlation |
| `file_hasher.jk` | Hash critical Windows system files for tamper detection |

---

## `workspace/`

User working directory. `scratch.jk` is the default editor buffer. User-created files persist here between sessions.

---

## `output/`

Build artifacts — `.o` object files, `.ll` LLVM IR dumps, `.exe` native binaries. Git-ignored (`.gitkeep` only).

---

## `docs/`

Documentation:

| File | Contents |
|------|----------|
| `jockydocumentation.md` | Full language reference: syntax, types, all stdlib functions with examples |
| `systemarchitecture.md` | Architecture diagrams, every module explained, data flow |
| `codebase.md` | This file — every source file explained |

---

## `README.md`

GitHub README with project overview, setup instructions, usage examples, and feature list.
