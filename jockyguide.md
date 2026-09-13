# JOCKY Framework — User Guide

JOCKY is a kernel security research platform built around a custom compiled language (`.jk`). It combines a full compiler pipeline, a BYOVD exploitation engine, user-mode evasion techniques, and a C2 framework — all accessible from a single TUI.

---

## Table of Contents

1. [What JOCKY Is](#1-what-jocky-is)
2. [Installation](#2-installation)
3. [How to Run](#3-how-to-run)
4. [TUI Walkthrough](#4-tui-walkthrough)
5. [JOCKY Language Quick Reference](#5-jocky-language-quick-reference)
6. [Built-in Scripts](#6-built-in-scripts)
7. [Standard Library Reference](#7-standard-library-reference)
8. [CLI Reference](#8-cli-reference)
9. [Architecture Overview](#9-architecture-overview)

---

## 1. What JOCKY Is

JOCKY is three things at once:

**A compiled language**  
JOCKY (`.jk`) source compiles to LLVM IR through a 5-stage pipeline. You can either JIT-execute it instantly (no linker needed) or compile it to a standalone `.exe` with four obfuscation passes that make every binary unique.

**A kernel security toolkit**  
The BYOVD engine loads signed vulnerable kernel drivers (via the LOLDrivers database), exploits their IOCTL interface for arbitrary kernel read/write, enumerates process-notify callbacks, and identifies EDR modules running at ring 0.

**A research environment**  
The TUI exposes every capability through menus: run scripts, inspect the compiler pipeline step-by-step, apply evasion techniques, or manage a C2 server — all from one interface.

---

## 2. Installation

### Prerequisites

- Python 3.10+
- `llvmlite` — LLVM Python bindings (IR building, MCJIT, object emission)
- `rich` — TUI rendering
- **Windows only — native build:** MinGW-w64 (gcc) in PATH

### Quick setup

```bash
## Windows
setup.bat

## Linux / macOS
chmod +x setup.sh && ./setup.sh
```

The setup scripts run `pip install -r requirements.txt` and, on Windows, attempt to locate or download MinGW gcc.

### Manual install

```bash
pip install llvmlite rich
```

---

## 3. How to Run

### Interactive TUI (recommended)

```bash
## Windows
jocky.bat

## Linux / macOS
./jocky.sh

## Or directly:
python jocky_terminal.py
```

### CLI — run a script

```bash
python jocky.py run scripts/byovd_scanner.jk
```

### CLI — build a native binary

```bash
python jocky.py build scripts/byovd_scanner.jk
```

### CLI — inspect pipeline stages

```bash
python jocky.py tokens scripts/byovd_scanner.jk
python jocky.py ast    scripts/byovd_scanner.jk
python jocky.py ir     scripts/byovd_scanner.jk
```

---

## 4. TUI Walkthrough

Launch the TUI with `jocky.bat` / `./jocky.sh` / `python jocky_terminal.py`. You are presented with the main menu:

```
[1] Pre-built Scripts
[2] Custom Code Editor
[3] Pipeline Inspector
[4] Build
[5] BYOVD Engine
[6] Evasion Engine
[7] C2 Management
[8] Language Reference
[9] About
```

---

### Menu 1 — Pre-built Scripts

Lists all 11 `.jk` scripts in the `scripts/` directory. Select a script by number to open its **action submenu**:

```
[1] Run JIT (clean)         Compile + execute immediately via MCJIT
[2] Run JIT + Obfuscation   JIT with all four obfuscation passes active
[3] Run Kernel Mode         JOCKY_KERNEL_MODE=1 — activates real kernel path
[4] Build Native Binary     Compile to .exe via gcc/MinGW (obfuscated)
[5] View Source             Syntax-highlighted source view
[6] Show Tokens             First 80 lexer tokens
[7] Show AST                Function names, parameters, statement counts
[8] Show LLVM IR            First 5000 chars of generated LLVM IR
[9] Pipeline Summary        Full compile with IR dump for analysis
```

**Run JIT (clean)** — the fastest path for testing. No disk output; everything runs in-process.

**Run Kernel Mode** — sets the `JOCKY_KERNEL_MODE` environment variable before running. The BYOVD engine switches from simulate mode to live kernel operations (requires admin + loaded driver).

**Build Native Binary** — prompts for obfuscation options, then produces a `.exe` in `output/`. The binary has a unique SHA-256 every compile due to obfuscation passes.

**Show Tokens / AST / IR** — use these to understand what the compiler is doing at each stage, or to debug a `.jk` script you are writing.

---

### Menu 2 — Custom Code Editor

An interactive editor for `workspace/scratch.jk`. Write JOCKY code, save with `Ctrl+S`, and run it directly from within the editor. The file persists between sessions.

---

### Menu 3 — Pipeline Inspector

Step through the compiler pipeline for any `.jk` file:

- **Tokens** — raw token stream from the lexer
- **AST** — structured function and statement tree from the parser
- **Semantic** — type-check result and any errors
- **IR** — full LLVM IR module text

Useful for learning the language or diagnosing compile errors.

---

### Menu 4 — Build

Batch compile options:

- **Compile current script** — compile to `.exe` with full obfuscation
- **Emit IR only** — save the LLVM IR to `output/<name>.ll` without linking
- **Debug build** — compile with `--no-obfuscate` for readable IR

Output goes to `output/`. Every native build produces a different binary hash.

---

### Menu 5 — BYOVD Engine

Direct access to the BYOVD subsystem without writing a `.jk` script:

- **Scan drivers** — run `DriverScanner.scan()` against the LOLDrivers database; shows risk, CVE, path for each match
- **Get kernel base** — resolve ntoskrnl.exe base address via `NtQuerySystemInformation(11)`
- **Enumerate callbacks** — list all `PspCreateProcessNotifyRoutine` entries with module classification
- **Blind EDR callbacks** — null all non-Microsoft callback pointers

In **simulate mode** (default), all kernel operations return realistic fake data; no kernel access is attempted. Set `JOCKY_KERNEL_MODE=1` or load a vulnerable driver to activate the live path.

---

### Menu 6 — Evasion Engine

Four user-mode evasion techniques:

| Technique | Description |
|-----------|-------------|
| API Unhooking | Compare ntdll.dll on-disk vs in-memory; restore hooked export prologues |
| Direct Syscalls | Extract SSNs from on-disk ntdll, build inline `syscall` stubs |
| DLL Injection | Classic (`LoadLibraryW`) or reflective (find `ReflectiveDllMain` export) |
| Process Hollowing | Create suspended host, unmap, map payload PE, fix relocations, resume |
| Thread Hijacking | Suspend thread, redirect RIP to shellcode + trampoline, resume |

---

### Menu 7 — C2 Management

Manage a command-and-control server and connected agents:

- **Start server** — launch the asyncio C2 server (configurable host:port, optional TLS)
- **Connect agent** — run `c2/agent.py` to connect this machine as an agent
- **Configure domain fronting** — set CDN front domain + real C2 hostname for traffic blending
- **List agents** — show connected agents with uptime and idle time
- **Execute code on all agents** — broadcast a JOCKY script or code snippet

---

### Menu 8 — Language Reference

Inline syntax quick-reference and stdlib function listing. No external docs required.

---

## 5. JOCKY Language Quick Reference

### Function

```jocky
func name(param : type) -> returnType {
    ## body
}

func start() -> nothing {
    report(`entry point`)
}
```

### Variables

```jocky
var x   : num  := 42            ## declare
var s   : text := `hello`       ## string (backtick)
var b   : flag := yes           ## boolean
var h   : raw  := byovd_scan()  ## opaque handle

x <- x + 1                      ## reassign with <-
```

### Types

| Type | Meaning |
|------|---------|
| `num` | 64-bit integer |
| `dec` | 64-bit float |
| `text` | String (backtick literals) |
| `flag` | Boolean (`yes` / `no`) |
| `raw` | Opaque handle from stdlib calls |
| `nothing` | Void (return type only) |

### Operators

| Symbol | Meaning |
|--------|---------|
| `is` | equal |
| `isnt` | not equal |
| `gt` `lt` `gte` `lte` | > < >= <= |
| `also` | logical AND |
| `or` | logical OR |
| `flip` | logical NOT |
| `mod` | modulo |
| `<-` | reassignment |
| `:=` | declaration assignment |

### Control flow

```jocky
check (x gt 0) {
    report(`positive`)
} otherwise {
    report(`non-positive`)
}

var i : num := 0
loop (i lt 10) {
    i <- i + 1
}

give value   ## return value
give         ## return void (early exit)
stop         ## break
skip         ## continue
```

### Comments

```jocky
## single line comment
```

### String literals

Strings always use backticks: `` `hello world` ``

---

## 6. Built-in Scripts

All scripts live in `scripts/`. Run any of them from Menu 1 in the TUI or via `python jocky.py run scripts/<name>.jk`.

| Script | What it does |
|--------|-------------|
| `byovd_scanner.jk` | Scan system drivers against LOLDrivers DB — risk level, CVE, path |
| `kernel_recon.jk` | Resolve kernel base, enumerate callbacks, identify EDR, optionally blind |
| `proc_scanner.jk` | Enumerate every running process and classify by threat level |
| `resource_monitor.jk` | Detect resource-abusing malware (miners, worms, RATs) via process scan |
| `threat_hunter.jk` | Full-spectrum hunt: processes + network + registry + file in one script |
| `registry_inspector.jk` | Inspect Winlogon, Defender policy, LSA protection, autorun locations |
| `sys_info.jk` | System triage: process categories, registry build info, network snapshot |
| `net_monitor.jk` | TCP connection snapshot cross-referenced with process list |
| `net_logger.jk` | Repeated network + process snapshots building a monitoring timeline |
| `packet_sniffer.jk` | Passive packet capture with sniffer/tunneling process correlation |
| `file_hasher.jk` | Hash critical Windows system files for tamper detection |

---

## 7. Standard Library Reference

### Output

| Function | Signature | Description |
|----------|-----------|-------------|
| `report` | `(msg : text)` | Print to stdout |

### Process

| Function | Signature | Description |
|----------|-----------|-------------|
| `procs_list` | `() -> raw` | Enumerate all running processes |
| `proc_count` | `(p : raw) -> num` | Number of processes |
| `proc_name` | `(p : raw, i : num) -> text` | Process name at index |
| `proc_pid` | `(p : raw, i : num) -> num` | PID at index |
| `proc_kill` | `(pid : num)` | Terminate process (safe mode logs only) |
| `proc_mem_read` | `(pid : num, addr : num, size : num) -> raw` | Read remote process memory |

### Network

| Function | Signature | Description |
|----------|-----------|-------------|
| `net_conns` | `() -> raw` | TCP connection snapshot |
| `net_sniff` | `(duration_ms : num) -> raw` | Capture traffic for given duration |

### Registry (Windows)

| Function | Signature | Description |
|----------|-----------|-------------|
| `reg_read` | `(key : text, value : text) -> text` | Read single HKLM registry value |
| `reg_list` | `(key : text) -> raw` | Enumerate subkeys under HKLM path |

### File System

| Function | Signature | Description |
|----------|-----------|-------------|
| `file_list` | `(path : text) -> raw` | List directory contents |
| `file_read` | `(path : text) -> text` | Read file (up to 65536 bytes) |

### System

| Function | Signature | Description |
|----------|-----------|-------------|
| `sys_info` | `() -> text` | OS version string |
| `hash_file` | `(path : text) -> raw` | SHA-256 of a file |

### BYOVD / Driver Scanner

| Function | Signature | Description |
|----------|-----------|-------------|
| `byovd_scan` | `() -> raw` | Scan drivers vs LOLDrivers DB |
| `byovd_driver_count` | `(r : raw) -> num` | Number of vulnerable drivers found |
| `byovd_driver_name` | `(r : raw, i : num) -> text` | Driver filename |
| `byovd_driver_path` | `(r : raw, i : num) -> text` | Full driver path |
| `byovd_driver_cve` | `(r : raw, i : num) -> text` | CVE identifier |
| `byovd_driver_risk` | `(r : raw, i : num) -> text` | Risk level: CRITICAL / HIGH / MEDIUM / LOW |
| `byovd_load` | `()` | Load vulnerable driver (sim-safe) |
| `byovd_unload` | `()` | Unload driver (sim-safe) |

### Kernel Operations

| Function | Signature | Description |
|----------|-----------|-------------|
| `kernel_base` | `() -> num` | Resolve ntoskrnl.exe base VA |
| `kernel_enum_callbacks` | `() -> raw` | Enumerate PspCreateProcessNotifyRoutine |
| `kernel_callback_count` | `(cb : raw) -> num` | Number of callbacks |
| `kernel_callback_addr` | `(cb : raw, i : num) -> num` | Callback address (lock bits masked) |
| `kernel_callback_module` | `(cb : raw, i : num) -> text` | Module owning callback |
| `kernel_read` | `(addr : num, size : num) -> raw` | Read kernel memory |
| `kernel_write` | `(addr : num, value : num)` | Write kernel memory (sim-suppressed) |
| `kernel_patch_callback` | `(addr : num) -> num` | Null one callback pointer |
| `kernel_blind_edr` | `() -> num` | Null all non-Microsoft callbacks |

---

## 8. CLI Reference

### `python jocky.py run <script.jk>`

Compile and JIT-execute a script immediately. No output files created.

```bash
python jocky.py run scripts/byovd_scanner.jk
python jocky.py run scripts/kernel_recon.jk --obfuscate-jit
```

### `python jocky.py build <script.jk>`

Compile to native `.exe`. Output in `output/`.

```bash
python jocky.py build scripts/proc_scanner.jk
python jocky.py build scripts/threat_hunter.jk --emit-ir
python jocky.py build scripts/byovd_scanner.jk --no-obfuscate
```

### `python jocky.py tokens <script.jk>`

Print the token stream from the lexer.

### `python jocky.py ast <script.jk>`

Print the AST (function list, parameter and statement counts).

### `python jocky.py ir <script.jk>`

Generate and print the LLVM IR without executing or linking.

### `python jocky.py byovd`

Run the BYOVD scanner directly (no `.jk` script needed).

### Flags

| Flag | Effect |
|------|--------|
| `--run` | JIT execute (same as `run` subcommand) |
| `--emit-ir` | Write LLVM IR to `output/<name>.ll` |
| `--no-obfuscate` | Skip obfuscation passes |
| `--obfuscate-jit` | Apply obfuscation passes even in JIT mode |
| `-o <dir>` | Output directory (default: `output/`) |

---

## 9. Architecture Overview

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

### Compiler pipeline

```
source.jk
   │
   ▼ Lexer (lexer.py / tokens.py)
   │ Token stream
   ▼ Parser (parser.py)
   │ AST
   ▼ Semantic analyser (semantic.py)
   │ Type-checked AST
   ▼ Code generator (codegen.py)
   │ LLVM IR module
   ▼ Obfuscation passes (passes.py)
   │ 1. Build-ID global   2. XOR string encrypt
   │ 3. Entropy global    4. Dead code functions
   │
   ├── JIT (MCJIT) ──── stdlib.py callbacks ──── output to stdout
   │
   └── Object emit ──── forensics.o + import shim ──── gcc ──── output/*.exe
```

### BYOVD flow

```
byovd/scanner.py  ──  SHA-256 + filename scan  ──  byovd/db/loldrivers.json
byovd/loader.py   ──  CreateServiceW / StartServiceW / DeviceIoControl
byovd/kernel.py   ──  NtQuerySystemInformation + RTCore64 IOCTL
                      kernel_base / read_memory / write_memory / enum_callbacks
```

### Key directories

| Directory | Contents |
|-----------|----------|
| `compiler/jocky/` | Language compiler modules (lexer, parser, semantic, codegen, passes, stdlib) |
| `compiler/stdlib/` | C implementations of stdlib (forensics.c / forensics.h) |
| `byovd/` | BYOVD engine: scanner, loader, kernel interface, LOLDrivers DB |
| `evasion/` | API unhooking, direct syscalls, injection, hollowing, thread hijacking |
| `c2/` | Asyncio C2 server, agent, domain fronting transport |
| `scripts/` | 11 pre-built `.jk` recon and analysis scripts |
| `workspace/` | User working directory; scratch.jk is the editor buffer |
| `output/` | Build artifacts: `.o`, `.ll`, `.exe` |
| `docs/` | Reference documentation |

---

*For language syntax details see `docs/jockydocumentation.md`. For codebase internals see `docs/codebase.md`. For architecture diagrams see `docs/systemarchitecture.md`.*
