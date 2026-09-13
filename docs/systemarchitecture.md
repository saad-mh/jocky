# JOCKY Framework — System Architecture

## High-Level Overview

JOCKY is a three-layer platform:

```
┌─────────────────────────────────────────────────────────────────┐
│                      JOCKY Framework                            │
│                                                                 │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────────────┐  │
│  │  Language    │  │  Evasion     │  │  C2 Framework        │  │
│  │  Compiler    │  │  Engine      │  │  (Server + Agent)    │  │
│  └──────┬───────┘  └──────┬───────┘  └──────────┬───────────┘  │
│         │                 │                      │              │
│  ┌──────▼───────────────────────────────────────▼───────────┐  │
│  │               BYOVD Engine (Kernel Layer)                 │  │
│  │  RTCore64  •  Kernel R/W  •  Callback Enum  •  Scanner   │  │
│  └───────────────────────────────────────────────────────────┘  │
│                                                                 │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │               TUI  (jocky_terminal.py)                    │  │
│  └───────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
```

---

## Module 1 — Language Compiler

### Purpose

Compile `.jk` source files into native Windows executables or JIT-execute them directly. Every compiled binary is unique due to four obfuscation passes and per-build import table variation.

### Pipeline

```
source.jk
    │
    ▼
┌─────────┐     ┌─────────┐     ┌───────────┐     ┌─────────────┐
│  Lexer  │────▶│ Parser  │────▶│ Semantic  │────▶│  CodeGen    │
│ (lexer) │     │(parser) │     │(semantic) │     │ (codegen)   │
└─────────┘     └─────────┘     └───────────┘     └──────┬──────┘
                                                          │ LLVM IR module
                                                          ▼
                                               ┌─────────────────────┐
                                               │  ObfuscationPasses  │
                                               │  1. Build-ID        │
                                               │  2. XOR strings     │
                                               │  3. Entropy global  │
                                               │  4. Dead functions  │
                                               └──────────┬──────────┘
                                                          │
                               ┌──────────────────────────┤
                               │                          │
                               ▼                          ▼
                        ┌─────────────┐        ┌──────────────────┐
                        │  MCJIT run  │        │  Object emit     │
                        │  (--run)    │        │  + gcc link      │
                        │  stdlib.py  │        │  + forensics.o   │
                        │  callbacks  │        │  + import shim   │
                        └─────────────┘        └──────────────────┘
                                                        │
                                                        ▼
                                               output/program.exe
                                               (unique SHA-256 every build)
```

### Key Files

| File | Role |
|------|------|
| `compiler/jocky/lexer.py` | Tokenises `.jk` source into token stream |
| `compiler/jocky/parser.py` | Builds AST from token stream |
| `compiler/jocky/semantic.py` | Type-checks AST, catches type errors |
| `compiler/jocky/codegen.py` | Generates LLVM IR from AST using llvmlite |
| `compiler/jocky/passes.py` | Applies 4 obfuscation passes to IR module |
| `compiler/jocky/stdlib.py` | Python callbacks for JIT mode — 33 functions covering output, process, network, registry, file system, BYOVD, and kernel operations |
| `compiler/compiler.py` | Orchestrates the full pipeline, generates per-build import shim |
| `compiler/stdlib/forensics.c` | C implementation of all stdlib functions (linked into .exe) |
| `compiler/stdlib/forensics.h` | Header declarations for forensics.c |

### Obfuscation Detail

```
Pass 1: Build-ID
  _jk_build_id = random 16 bytes (os.urandom)
  → binary SHA-256 changes every compile

Pass 2: XOR String Encryption
  key = random 1-byte per build
  all string globals XOR-encrypted in IR
  jk_xordecrypt() in forensics.c decrypts at runtime
  → no plaintext strings in binary

Pass 3: Entropy Global
  _jk_entropy = random 64-bit value
  → increases binary entropy, defeats compression-based detection

Pass 4: Dead Code
  companion_N() functions with opaque predicate (N*(N+1))%2==0
  always true at compile time, looks real to static analysis
  → increases code complexity, breaks pattern signatures

Pass 5 (link-time): Import Table Variation
  _generate_import_variation_shim() picks 4–12 random decoy functions
  from 14 different DLLs (user32, shell32, wininet, gdi32, ole32, ...)
  → imphash changes every build, defeats AV import-hash signatures
```

---

## Module 2 — BYOVD Engine

### Purpose

Load a signed vulnerable kernel driver, exploit its IOCTL interface for arbitrary kernel read/write, enumerate kernel callbacks, and identify EDR modules loaded in kernel space.

### Architecture

```
User Mode
  │
  │  1. CreateServiceW + StartServiceW
  ▼
┌─────────────────────────────┐
│   loader.py / DriverLoader  │   Loads RTCore64.sys into kernel
│   CreateFileW(\\.RTCore64)  │   Opens device handle
└─────────────┬───────────────┘
              │
              │  DeviceIoControl
              │  IOCTL 0x80002048 (read)
              │  IOCTL 0x8000204C (write)
              ▼
Kernel Mode
┌─────────────────────────────┐
│    RTCore64.sys             │   CVE-2019-16098
│    Arbitrary kernel R/W     │   Any physical/virtual kernel address
└─────────────┬───────────────┘
              │
              ├──── kernel_base resolution ──────────────────────────────────────┐
              │     Method 1: NtQuerySystemInformation(11)                        │
              │       raw buffer → struct.unpack_from('<Q', buf, 8+16)            │
              │       avoids c_void_p sign truncation for addrs > 0x7FFF...       │
              │     Method 2: psapi!EnumDeviceDrivers with c_uint64 array         │
              │                                                                   │
              ├──── callback enumeration ─────────────────────────────────────────┤
              │     PE pattern scan of ntoskrnl.exe on disk:                      │
              │       find PsSetCreateProcessNotifyRoutine export                 │
              │       scan for LEA R?X,[RIP+disp32] (48/4C 8D 05/0D/15/1D)       │
              │       → RIP+disp32 = PspCreateProcessNotifyRoutine array          │
              │     Read array entries via RTCore64 R IOCTL                       │
              │     Mask lowest 4 bits (lock bits): addr & ~0xF                   │
              │     Classify: module map lookup → is_microsoft?                   │
              │                                                                   │
              └──── driver scanner ────────────────────────────────────────────────┘
                    scanner.py: SHA-256 cross-ref + filename fallback
                    forensics.c byovd_scan(): self-contained SHA-256 + filename
                    LOLDrivers DB: 40+ entries (loldrivers.json)
```

### _is_microsoft_address Fix

Old (broken): `0xFFFFF80000000000 <= addr <= 0xFFFFF80040000000`
- Only covered ntoskrnl/hal range
- Misclassified tcpip.sys, ntfs.sys, storport.sys as EDR

New (correct): build module map from NtQuerySystemInformation, check `addr` falls within a module's `[base, base+size)`, then look up module name in `_MICROSOFT_MODULES` whitelist set (30+ names).

### Key Files

| File | Role |
|------|------|
| `byovd/kernel.py` | KernelInterface class — kernel base, callbacks, R/W, module map |
| `byovd/loader.py` | DriverLoader — CreateService, StartService, DeviceIoControl |
| `byovd/scanner.py` | DriverScanner — SHA-256 + filename scan against loldrivers.json |
| `byovd/db/loldrivers.json` | 40+ vulnerable driver entries with CVE and hash data |

---

## Module 3 — Evasion Engine

### Purpose

Bypass EDR/AV monitoring at the user-mode level using in-memory execution techniques that avoid touching disk or triggering common detection hooks.

### Techniques

```
evasion/
│
├── api_unhook.py ─── API Unhooking
│     Compare ntdll.dll on-disk vs in-memory (export by export)
│     Detect jmp/hotpatch hooks at function prologue
│     Restore hooked exports: VirtualProtectEx(RWX) + WriteProcessMemory
│     → EDR hooks in ntdll are removed, syscalls go through unhooked path
│
├── syscall.py ────── Direct Syscalls
│     Read on-disk ntdll.dll (before any hooks applied)
│     Parse export table → find Nt* function RVAs
│     Scan stub: look for MOV EAX, imm32 (opcode 0xB8) → extract SSN
│     Build stub: 4C 8B D1 / B8 xx xx 00 00 / 0F 05 / C3
│                 (mov r10,rcx / mov eax,SSN / syscall / ret)
│     VirtualAlloc(RWX) + memmove → call directly
│     → ntdll hooks are bypassed entirely; kernel sees direct INT/SYSCALL
│
├── inject.py ─────── DLL Injection
│     Classic: WriteProcessMemory(path) + CreateRemoteThread(LoadLibraryW)
│     Reflective: write full DLL bytes to remote process
│               find ReflectiveDllMain export
│               CreateRemoteThread(loader_addr, base_addr)
│               → DLL resolves its own imports and maps itself
│
├── hollow.py ─────── Process Hollowing
│     CreateProcessW(host, CREATE_SUSPENDED)
│     NtQueryInformationProcess → PEB.ImageBaseAddress
│     NtUnmapViewOfSection(hproc, old_base)
│     VirtualAllocEx(payload.ImageBase, payload.ImageSize, RWX)
│     WriteProcessMemory: headers + sections
│     Apply base relocations (IMAGE_REL_BASED_DIR64)
│     Patch PEB.ImageBaseAddress → new base
│     SetThreadContext: Rip = new entry point
│     ResumeThread
│     → host process shell, payload code runs
│
└── thread_hijack.py ─ Thread Hijacking
      CreateToolhelp32Snapshot + Thread32First/Next → enumerate TIDs
      OpenThread(THREAD_ALL_ACCESS)
      SuspendThread
      GetThreadContext → read Rip (offset 0xF8 in CONTEXT)
      VirtualAllocEx(trampoline) → shellcode + push(original_rip) + ret
      SetThreadContext → Rip = trampoline
      ResumeThread
      → thread executes shellcode then returns to original flow
```

---

## Module 4 — C2 Framework

### Purpose

Manage multiple compromised endpoints from a central server. Supports direct TCP connections, domain fronting through CDN infrastructure, and SOCKS5 proxy routing.

### Architecture

```
                        Internet / Network
                              │
                    ┌─────────▼──────────┐
                    │    CDN Edge Node   │  ← Network sees this (legitimate)
                    │  (*.cloudfront.net │
                    │   *.azureedge.net) │
                    └─────────┬──────────┘
                              │  TLS encrypted
                              │  Host: <real C2>  ← hidden inside TLS
                              ▼
                    ┌─────────────────────┐
                    │    C2 Server        │   c2/server.py
                    │    asyncio TCP      │   port 4444 (configurable)
                    │                     │
                    │  Agent Sessions:    │
                    │  SID-A ──────────── │──── Agent (endpoint 1)
                    │  SID-B ──────────── │──── Agent (endpoint 2)
                    │  SID-C ──────────── │──── Agent (endpoint 3)
                    │                     │
                    │  Management Shell:  │
                    │  list / exec / quit │
                    └─────────────────────┘

Agent (c2/agent.py):
  ┌─────────────────────────────────────────────────────────┐
  │  Connect → HELLO handshake → receive SID               │
  │  Heartbeat ping every 30s                               │
  │  On CMD: exec_script / exec_code / shell               │
  │  Run JOCKY compiler locally → return output            │
  │  Automatic reconnect on disconnect                      │
  └─────────────────────────────────────────────────────────┘

Domain Fronting (c2/fronting.py):
  ┌─────────────────────────────────────────────────────────┐
  │  TCP connect → CDN front domain (visible to network)   │
  │  TLS handshake: SNI = CDN front                        │
  │  HTTP Host header: real C2 hostname (encrypted in TLS) │
  │  CDN routes based on Host header to real backend       │
  │  Optional: SOCKS5 proxy as first hop                   │
  └─────────────────────────────────────────────────────────┘
```

### Protocol

```
Client → Server:  {"type": "HELLO", "version": "1", "info": {...}}
Server → Client:  {"type": "HELLO", "sid": "a1b2c3d4"}

Server → Client:  {"type": "CMD", "cmd_id": "uuid", "action": "exec_code", "code": "..."}
Client → Server:  {"type": "RESULT", "cmd_id": "uuid", "status": "ok", "output": "..."}

Client → Server:  {"type": "PING"}
Server → Client:  {"type": "PONG"}
```

All messages are newline-delimited JSON over TCP (optionally wrapped in TLS).

---

## Module 5 — TUI (jocky_terminal.py)

A menu-driven terminal UI built with Rich that exposes all framework capabilities:

```
Main Menu
│
├── 1. Pre-built Scripts      Browse .jk scripts → 9-option action submenu per script
│     └── Script Action Menu
│           ├── 1. Run JIT (clean)         Compile + JIT-execute immediately
│           ├── 2. Run JIT + Obfuscation   JIT with all four obfuscation passes
│           ├── 3. Run Kernel Mode         Set JOCKY_KERNEL_MODE=1 then JIT-execute
│           ├── 4. Build Native Binary     Compile to .exe via gcc/MinGW
│           ├── 5. View Source             Rich syntax-highlighted source view
│           ├── 6. Show Tokens             First 80 lexer tokens
│           ├── 7. Show AST               Function names + statement counts
│           ├── 8. Show LLVM IR            First 5000 chars of generated IR
│           └── 9. Pipeline Summary        Full compile with emit_ir for analysis
├── 2. Custom Code Editor     Write/edit/run JOCKY code interactively
├── 3. Pipeline Inspector     Inspect tokens / AST / IR / semantic
├── 4. Build                  Compile to native exe, batch build
├── 5. BYOVD Engine           Driver scan, kernel R/W, callback enum, blind
├── 6. Evasion Engine         API unhook, syscalls, hollowing, injection, hijack
├── 7. C2 Management          Start server, connect agent, configure fronting
├── 8. Language Reference     Inline syntax + stdlib quick-ref
└── 9. About                  Framework overview
```

---

## Data Flow — Full Attack Scenario

```
1. Reconnaissance
   jk script → procs_list() → identifies EDR process names
   jk script → byovd_scan() → finds RTCore64.sys on system

2. BYOVD Exploitation
   loader.py → CreateServiceW(RTCore64.sys) → kernel driver loaded
   kernel.py → get_kernel_base() → resolve ntoskrnl VA
   kernel.py → enum_process_callbacks() → find EDR callbacks
   kernel.py → blind_callbacks() → null EDR callback pointers

3. Evasion
   api_unhook.py → restore ntdll hooks → clean syscall path
   syscall.py → direct syscalls → bypass any remaining hooks

4. Payload Delivery
   hollow.py → hollow notepad.exe → inject payload PE
   inject.py → reflective DLL → load payload in target process

5. Persistence / C2
   c2/agent.py → connect to C2 server
   c2/fronting.py → route through CDN → evade network monitoring
   server.py → dispatch commands → execute JOCKY scripts remotely
```

---

## Cross-Platform Support

| Feature | Windows | Linux |
|---------|---------|-------|
| Process enumeration | EnumProcesses + PSAPI | /proc/<pid>/comm |
| Network connections | GetExtendedTcpTable | /proc/net/tcp |
| Kernel base | NtQuerySystemInformation(11) | /proc/modules |
| Driver scan | System32\drivers\*.sys | /lib/modules/*/kernel/** |
| Registry | HKLM\Services | /proc/modules |
| SHA-256 | Inline C (no openssl) | Inline C (no openssl) |
| BYOVD kernel R/W | RTCore64 IOCTL | N/A (no Windows driver) |
| Evasion engine | Full (Windows APIs) | N/A |
| C2 server/agent | Yes (asyncio) | Yes (asyncio) |
| Domain fronting | Yes | Yes |
| JOCKY compiler | Yes (full) | Yes (JIT only) |

---

## Security Model

The framework operates at three privilege levels:

```
Ring 3 (User mode)
  • Compiler, TUI, C2, evasion techniques
  • Requires standard user privileges for most operations
  • Process hollowing, DLL injection: requires OpenProcess access to target

Ring 0 (Kernel mode) — via BYOVD
  • Kernel R/W via RTCore64 IOCTL
  • Callback enumeration and nulling
  • Requires: admin to load driver service (or pre-loaded driver)

Network layer
  • C2 traffic: any outbound port (443 recommended for CDN fronting)
  • Domain fronting: routes through legitimate CDN — no direct C2 IP visible
```
