# JOCKY Framework

Advanced kernel security research platform with an independent compiled language, polymorphic binary generation, BYOVD exploitation engine, in-memory evasion toolkit, and a C2 framework with CDN domain fronting.

---

## Features

### Independent Language Compiler
- Custom `.jk` language compiled via LLVM to native `.exe` (no Python runtime on target)
- JIT execution mode via MCJIT for rapid testing
- Full pipeline: Lexer → Parser → Semantic → CodeGen → Obfuscation → Native binary

### Polymorphic Binary Generation (4 + 1 passes)
1. **Per-build ID** — 16-byte random constant; every binary has a unique hash
2. **XOR string encryption** — all string literals encrypted with a per-build key; no plaintext strings in binary
3. **Entropy global** — random 64-bit value; defeats entropy-based detection
4. **Dead code injection** — opaque-predicate companion functions; breaks pattern signatures
5. **Import table variation** — per-build random subset of decoy imports from 14+ DLLs; imphash changes every compile

### BYOVD Engine
- Vulnerable driver loader (RTCore64.sys, CVE-2019-16098)
- Kernel base resolution: raw `NtQuerySystemInformation(11)` buffer parse + `psapi!EnumDeviceDrivers` fallback (fixes HVCI/VBS zero-return bug)
- Callback enumeration: PE scan of ntoskrnl.exe → `PspCreateProcessNotifyRoutine` → RTCore64 kernel read
- EDR module classification via module map (not narrow address range heuristic)
- Callback nulling (EDR blind)
- **LOLDrivers DB**: 40+ entries with SHA-256 cross-reference + filename fallback

### Evasion Engine
- **API Unhooking** — detect and restore EDR hooks in ntdll.dll by comparing on-disk vs in-memory export bytes
- **Direct Syscalls** — extract SSNs from on-disk ntdll, build `syscall` stubs in RWX memory, bypass all ntdll hooks
- **Process Hollowing** — `NtUnmapViewOfSection` + PE remap + base relocation fixup + thread context redirect
- **DLL Injection** — LoadLibraryW injection and reflective DLL injection (no LoadLibrary on target)
- **Thread Hijacking** — suspend thread, redirect RIP to shellcode with trampoline back to original flow

### C2 Framework
- Asyncio multi-agent server with management shell (`list`, `exec`, `execall`)
- Agent with heartbeat, auto-reconnect, remote JOCKY script/code execution
- **Domain fronting** — HTTP `Host:` header carries real C2 hostname; TCP/TLS SNI points to CDN edge node; network sees only legitimate CDN traffic
- **SOCKS5 proxy** — optional double-hop routing for agent traffic
- Optional TLS encryption on the C2 channel

### Cross-Platform
- Windows 10/11 (primary): full feature set
- Linux: process enumeration (`/proc`), network connections (`/proc/net/tcp`), driver scan (`/lib/modules`), C2, compiler JIT

---

## Quick Start

### Requirements

- Python 3.10+
- `pip install llvmlite rich`
- MinGW gcc (for native `.exe` builds): `winget install mingw` or download from mingw-w64.org

### Setup

```bash
# Windows
setup.bat

# Linux / macOS
chmod +x setup.sh && ./setup.sh
```

### Run the TUI

```bash
python jocky_terminal.py
```

### Compile a script directly

```bash
# JIT execute (no linker needed)
python jocky.py scripts/kernel_recon.jk --run

# Build native exe
python build_stdlib.py          # build forensics.o (once)
python jocky.py scripts/kernel_recon.jk
output/kernel_recon.exe
```

---

## Language Quick Reference

```jocky
func start() {
    // System fingerprint
    report(system_info());

    // Process enumeration
    let p: proc = procs_list();
    let n: int = proc_count(p);
    for (let i: int = 0; i < n; i++) {
        report(proc_name(p, i));
    }

    // BYOVD vulnerable driver scan
    let m: mem = byovd_scan();
    let nd: int = byovd_count(m);
    for (let i: int = 0; i < nd; i++) {
        report(byovd_name(m, i));
        report(byovd_cve(m, i));
        report(byovd_hash(m, i));   // SHA-256 of driver file
    }

    // Kernel base
    let base: int = kernel_base();
    report("Kernel base resolved");
}
```

Types: `int`, `string`, `bool`, `proc`, `conn`, `mem`

Full documentation: [`docs/jockydocumentation.md`](docs/jockydocumentation.md)

---

## Project Structure

```
JOCKY Framework/
│
├── jocky_terminal.py        TUI entry point
├── jocky.py                 CLI wrapper
├── jocky.bat / jocky.sh     OS launchers
├── setup.bat / setup.sh     First-run setup
├── requirements.txt
│
├── compiler/
│   ├── compiler.py          Full pipeline + import variation
│   ├── jocky/
│   │   ├── lexer.py
│   │   ├── parser.py
│   │   ├── semantic.py
│   │   ├── codegen.py
│   │   ├── passes.py        4 obfuscation passes
│   │   └── stdlib.py        JIT callbacks (Python)
│   └── stdlib/
│       ├── forensics.c      Native stdlib (linked into .exe)
│       └── forensics.h
│
├── byovd/
│   ├── kernel.py            KernelInterface — base, callbacks, R/W
│   ├── loader.py            DriverLoader — CreateService, IOCTL
│   ├── scanner.py           DriverScanner — SHA-256 + filename
│   └── db/
│       └── loldrivers.json  40+ vulnerable driver entries
│
├── evasion/
│   ├── api_unhook.py        ntdll hook detection + restoration
│   ├── syscall.py           Direct syscall stubs from on-disk SSNs
│   ├── inject.py            LoadLibrary + reflective DLL injection
│   ├── hollow.py            Process hollowing
│   └── thread_hijack.py     Thread RIP hijacking
│
├── c2/
│   ├── server.py            Asyncio C2 server, multi-agent
│   ├── agent.py             C2 agent, auto-reconnect, JOCKY execution
│   └── fronting.py          Domain fronting + SOCKS5 proxy
│
├── scripts/                 Pre-built .jk recon scripts
├── workspace/               User code editor workspace
├── output/                  Build artifacts (.exe, .o, .ll)
└── docs/
    ├── jockydocumentation.md
    ├── systemarchitecture.md
    └── codebase.md
```

---

## Architecture Overview

```
User Mode
  ┌──────────────────────────────────────────────┐
  │  TUI (jocky_terminal.py)                     │
  │  ├── Compiler Pipeline (.jk → LLVM → exe)    │
  │  ├── Evasion Engine (unhook/syscall/hollow)  │
  │  └── C2 Management (server/agent/fronting)   │
  └──────────────────────┬───────────────────────┘
                         │  RTCore64 IOCTL
Kernel Mode              ▼
  ┌──────────────────────────────────────────────┐
  │  RTCore64.sys (CVE-2019-16098)               │
  │  Arbitrary kernel R/W                        │
  │  → Callback enum & blind                     │
  └──────────────────────────────────────────────┘
```

---

## C2 Domain Fronting

```
[Agent] → SOCKS5 proxy (optional) → CDN edge (SNI: cdn.example.com)
                                         │
                                         │ TLS decrypted
                                         │ Host: real-c2.internal ← routes here
                                         ▼
                                    [C2 Server]
```

Network monitoring sees connections only to the CDN domain. The actual C2 hostname never appears in cleartext on the wire.

---

## Documentation

| Document | Contents |
|----------|----------|
| [Language Docs](docs/jockydocumentation.md) | Complete JOCKY syntax, all stdlib functions, examples |
| [System Architecture](docs/systemarchitecture.md) | Module diagrams, data flow, security model |
| [Codebase Reference](docs/codebase.md) | Every file explained with key functions |

---

## Problem Statement Coverage

| Requirement | Implementation |
|-------------|----------------|
| Independent compiled language | JOCKY: `.jk` → LLVM IR → native `.exe` |
| Polymorphic binaries | 5-pass obfuscation: build-ID, XOR strings, entropy, dead code, import variation |
| BYOVD / LOTL | RTCore64.sys kernel R/W, callback enum, LOLDrivers DB (40+ entries) |
| In-memory execution | Process hollowing, reflective DLL injection, thread hijacking |
| Direct syscalls | SSN extraction from on-disk ntdll, RWX stub generation |
| API unhooking | On-disk vs in-memory comparison, VirtualProtectEx + WriteProcessMemory restore |
| Central management interface | Asyncio C2 server: multi-agent, exec, broadcast |
| CDN / domain fronting | Host: header spoofing through CDN edge, TLS SNI mismatch |
| SOCKS5 proxy routing | Full SOCKS5 handshake + auth, double-hop routing |
| Cross-platform | Windows (full), Linux (/proc, /lib/modules, asyncio C2) |
| Kernel callback blind | Null process-creation callbacks via RTCore64 kernel write |
