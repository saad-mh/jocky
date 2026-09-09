# JOCKY Terminal Application — Complete Guide

**JOCKY** is a compiled, statically-typed programming language designed for Windows forensics and cybersecurity tooling. This guide covers everything needed to set up, run, and use the JOCKY terminal application on any machine.

---

## Table of Contents

1. [What Is JOCKY?](#1-what-is-jocky)
2. [Folder Structure](#2-folder-structure)
3. [Prerequisites](#3-prerequisites)
4. [Setup (First-Time)](#4-setup-first-time)
5. [Running the Interactive TUI](#5-running-the-interactive-tui)
6. [Using the CLI](#6-using-the-cli)
7. [Pre-built Cybersecurity Scripts](#7-pre-built-cybersecurity-scripts)
8. [Writing Your Own Scripts](#8-writing-your-own-scripts)
9. [Inspecting the Compilation Pipeline](#9-inspecting-the-compilation-pipeline)
10. [Building Native Binaries](#10-building-native-binaries)
11. [JOCKY Language Reference](#11-jocky-language-reference)
12. [Troubleshooting](#12-troubleshooting)

---

## 1. What Is JOCKY?

JOCKY is a security-focused compiled language with three AV-evasion properties:

| Property | Description |
|---|---|
| **Custom syntax** | `.jk` files cannot be parsed by AV script engines |
| **XOR-encrypted strings** | String literals are encrypted in the compiled binary |
| **Polymorphic compilation** | Every compile produces a unique SHA-256 hash |

**Compilation pipeline:**

```
.jk source
  ↓  [1] Lexer        tokenise source text
  ↓  [2] Parser       build Abstract Syntax Tree
  ↓  [3] Semantic     type-check the AST
  ↓  [4] Codegen      emit LLVM IR
  ↓  [5] Obfuscation  XOR-encrypt strings + inject random build-ID
     ↙          ↘
  JIT mode       Native binary mode
  (Python MCJIT) (gcc links .o → .exe)
```

---

## 2. Folder Structure

```
JOCKY Application/
├── jocky_terminal.py      ← Main interactive TUI (run this)
├── jocky.py               ← CLI wrapper
├── jocky.bat              ← Windows shortcut: "jocky run script.jk"
├── jocky.sh               ← Linux/macOS shortcut
├── setup.bat              ← Windows first-time setup
├── setup.sh               ← Linux/macOS first-time setup
├── requirements.txt       ← Python dependencies
├── terminal_guide.md      ← This file
├── .gitignore
│
├── compiler/              ← Bundled JOCKY compiler (self-contained)
│   ├── compiler.py        ← Main compiler entry point
│   ├── build_stdlib.py    ← Builds stdlib/forensics.o via gcc
│   ├── jocky/             ← Compiler package
│   │   ├── tokens.py      ← Token type definitions
│   │   ├── lexer.py       ← Stage 1: Lexical analysis
│   │   ├── ast_nodes.py   ← AST node dataclasses
│   │   ├── parser.py      ← Stage 2: Recursive descent parser
│   │   ├── symbol_table.py← Scoped name registry
│   │   ├── semantic.py    ← Stage 3: Type checking
│   │   ├── codegen.py     ← Stage 4: LLVM IR generation
│   │   ├── passes.py      ← Stage 5: Obfuscation passes
│   │   └── stdlib.py      ← JIT-mode stdlib (Python ctypes callbacks)
│   └── stdlib/
│       ├── forensics.h    ← C stdlib API header
│       ├── forensics.c    ← C stdlib implementation
│       └── forensics.o    ← Built by setup (gitignored)
│
├── scripts/               ← Pre-built cybersecurity scripts
│   ├── proc_scanner.jk
│   ├── net_monitor.jk
│   ├── net_logger.jk
│   ├── packet_sniffer.jk
│   ├── resource_monitor.jk
│   ├── sys_info.jk
│   ├── file_hasher.jk
│   ├── registry_inspector.jk
│   └── threat_hunter.jk
│
├── workspace/             ← Your own scripts go here
│   └── example.jk
│
└── output/                ← Compiled artifacts (.o, .exe, .ll)
```

---

## 3. Prerequisites

| Requirement | Version | Notes |
|---|---|---|
| Python | 3.10+ | `python --version` |
| llvmlite | 0.39+ | Installed by setup |
| rich | 13.0+ | Optional — for the TUI colours |
| MinGW gcc | any | Only for native `.exe` output |

**Python download:** https://www.python.org/downloads/

**MinGW download (Windows):** https://www.mingw-w64.org/  
Install and add `C:\mingw64\bin` to your `PATH`.

---

## 4. Setup (First-Time)

Run **once** after cloning or copying the folder to a new machine.

### Windows

```bat
setup.bat
```

This will:
1. Check Python version
2. `pip install -r requirements.txt` (llvmlite + rich)
3. Test llvmlite import
4. Detect gcc and build `compiler/stdlib/forensics.o`

### Linux / macOS

```bash
bash setup.sh
```

Same steps as Windows — adapt gcc install to your distro:
```bash
# Ubuntu/Debian
sudo apt install gcc

# macOS (Xcode CLI tools)
xcode-select --install
```

### Manual (if setup scripts fail)

```bash
pip install llvmlite rich
python compiler/build_stdlib.py   # only if gcc is available
```

---

## 5. Running the Interactive TUI

The TUI is the primary way to use JOCKY. It provides menus for all features.

```bash
python jocky_terminal.py
```

On Windows you can also double-click `jocky.bat` without arguments.

### Main Menu

```
  [1]  Pre-built Cybersecurity Scripts
  [2]  Write / Edit Custom Script
  [3]  Inspect Script  (Tokens · AST · IR)
  [4]  Build Native Binary  (.exe)
  [5]  Language Reference
  [6]  About JOCKY
  [0]  Exit
```

### Navigation

- Type the number and press **Enter**
- At any sub-menu, press **0** to go back
- Press **Enter** at any "Press Enter to continue..." prompt

---

## 6. Using the CLI

The CLI is for power users and automation.

### General syntax

```
python jocky.py <command> <file.jk> [flags]
```

On Windows with `jocky.bat` on PATH:
```
jocky <command> <file.jk>
```

### Commands

| Command | Description | Example |
|---|---|---|
| `run` | JIT-execute (no linker needed) | `jocky run scripts/proc_scanner.jk` |
| `build` | Compile to native `.exe` | `jocky build scripts/threat_hunter.jk` |
| `show` | Print source with line numbers | `jocky show workspace/example.jk` |
| `tokens` | Print lexer token table | `jocky tokens scripts/net_monitor.jk` |
| `ast` | Print parsed AST | `jocky ast scripts/proc_scanner.jk` |
| `ir` | Print LLVM IR (clean) | `jocky ir scripts/sys_info.jk` |
| `ir-obf` | Print LLVM IR (obfuscated) | `jocky ir-obf scripts/proc_scanner.jk` |
| `inspect` | Full pipeline summary | `jocky inspect scripts/threat_hunter.jk` |

### Shorthand

A `.jk` file as the only argument runs it directly:

```bash
jocky script.jk              # same as:  jocky run script.jk
```

### Build flags

```bash
jocky build script.jk                    # with XOR obfuscation (default)
jocky build script.jk --no-obfuscate     # readable strings (debugging)
```

---

## 7. Pre-built Cybersecurity Scripts

All scripts live in `scripts/` and run in JIT mode without needing gcc.

### proc_scanner.jk — Process Scanner

Enumerates all running processes. Flags credential dumpers, backdoors, and suspicious tools.

```bash
jocky run scripts/proc_scanner.jk
```

Detects: `mimikatz.exe`, `pwdump.exe`, `nc.exe`, `wce.exe`, `xmrig.exe`, `psexec.exe`

---

### net_monitor.jk — Network Connection Monitor

Captures the active TCP/UDP connection table. Reports connection state and remote addresses.

```bash
jocky run scripts/net_monitor.jk
```

Useful for: detecting C2 beaconing, unexpected LISTEN ports (RDP/WinRM), data exfiltration channels.

---

### net_logger.jk — Network Connection Logger

Takes 5 repeated connection snapshots. Simulates a persistent logging loop.

```bash
jocky run scripts/net_logger.jk
```

Useful for: building connection timelines, detecting periodic beaconing patterns.

---

### packet_sniffer.jk — Passive Packet Sniffer

Runs 3 rounds of passive packet capture (2 seconds each). Analyzes payloads for cleartext credentials.

```bash
jocky run scripts/packet_sniffer.jk
```

Looks for: HTTP cleartext, FTP commands, Telnet sessions, unencrypted SMB, DNS tunneling.

---

### resource_monitor.jk — Resource Utilization Monitor

Collects CPU/memory snapshot. Scans for crypto-miner process names.

```bash
jocky run scripts/resource_monitor.jk
```

Detects: `xmrig.exe`, `minerd.exe`, `cgminer.exe`

---

### sys_info.jk — System Information Collector

Gathers OS version, hostname, architecture, and process/network baselines for forensic triage.

```bash
jocky run scripts/sys_info.jk
```

Useful for: incident report headers, pre/post comparison during IR.

---

### file_hasher.jk — File Integrity Checker

SHA-256 hashes critical Windows system binaries and security-sensitive executables.

```bash
jocky run scripts/file_hasher.jk
```

Files checked: `lsass.exe`, `svchost.exe`, `winlogon.exe`, `ntoskrnl.exe`, `powershell.exe`, etc.

Compare output against NSRL database or a known-good baseline to detect tampering.

---

### registry_inspector.jk — Registry Inspector

Reads autorun persistence keys and security policy settings from the Windows registry.

```bash
jocky run scripts/registry_inspector.jk
```

Keys inspected:
- `SOFTWARE\...\CurrentVersion\Run` / `RunOnce`
- `SYSTEM\...\Services`
- `SOFTWARE\...\Winlogon`
- Windows Defender disable flags

---

### threat_hunter.jk — Full Threat Hunting Suite

Runs all detection modules in sequence: process → network → persistence → file integrity → packet capture.

```bash
jocky run scripts/threat_hunter.jk
```

This is the **go-to script for a full endpoint threat hunt**.

---

## 8. Writing Your Own Scripts

### Quick start

1. Open `workspace/example.jk` in any text editor.
2. Write your JOCKY code.
3. Save the file.
4. Run it:

```bash
jocky run workspace/example.jk
```

### Via the TUI

From the main menu: `[2] Write / Edit Custom Script` → `[n] New script`  
The TUI will create the file and open it in your default editor.

### Script template

```jocky
## my_script.jk — description

func helper(msg : text) -> nothing {
    report(msg)
}

func start() -> nothing {
    report(`My JOCKY Script`)
    helper(`Hello!`)

    var count : num := 5
    var i : num := 0
    loop (i lt count) {
        report(`iteration`)
        i <- i + 1
    }
}
```

### Rules

- Every script **must** have `func start() -> nothing` — this is the entry point.
- All functions must be defined at top level (no nesting).
- Variables must always have an initializer: `var x : num := 0`
- String literals use **backticks**: `` `hello world` ``
- Comments use `##`: `## this is a comment`

---

## 9. Inspecting the Compilation Pipeline

JOCKY lets you see exactly what happens at each compiler stage.

### Via TUI

Main menu → `[3] Inspect Script` → enter a file path → choose a stage.

### Via CLI

```bash
# Print all stages as a summary table
jocky inspect scripts/proc_scanner.jk

# Stage 1: tokens
jocky tokens scripts/proc_scanner.jk

# Stage 2: AST tree
jocky ast scripts/proc_scanner.jk

# Stage 4: clean LLVM IR (readable strings)
jocky ir scripts/proc_scanner.jk

# Stage 5: obfuscated LLVM IR (XOR-encrypted strings, build ID injected)
jocky ir-obf scripts/proc_scanner.jk
```

### What each stage shows

| Stage | Command | What you see |
|---|---|---|
| Source | `show` | Numbered source lines |
| Lexer | `tokens` | Token type, value, line/col for every token |
| Parser | `ast` | Indented tree of AST nodes |
| Codegen | `ir` | Full LLVM IR text — readable strings |
| Obfuscation | `ir-obf` | LLVM IR with XOR-encrypted string globals, random build ID, entropy global |

### Understanding obfuscation in IR

Run `jocky ir-obf scripts/proc_scanner.jk` and look for:

```llvm
@.jk_str.0 = internal constant [14 x i8] c"\a9\b3\c1..."   ; XOR-encrypted "proc_scanner"
@_jocky_xor_key = i8 42                                      ; random XOR key (42 in this run)
@_jocky_build_id = internal constant [16 x i8] ...           ; random 16 bytes
@_jocky_entropy = internal constant i64 ...                  ; random 64-bit value
```

Run it again — `_jocky_build_id`, `_jocky_entropy`, and the XOR key all change → **different SHA-256 every compile**.

---

## 10. Building Native Binaries

Native binaries require:
1. `gcc` on PATH (MinGW on Windows)
2. `compiler/stdlib/forensics.o` (built by `setup.bat`)

### Build a script

```bash
jocky build scripts/proc_scanner.jk
```

Output goes to `output/proc_scanner.exe`.

### Build without obfuscation (debugging)

```bash
jocky build scripts/proc_scanner.jk --no-obfuscate
```

### Polymorphism demo

```bash
jocky build scripts/hello.jk
jocky build scripts/hello.jk
```

Both commands produce `proc_scanner.exe` from identical source — but with **different SHA-256 hashes**. This defeats AV hash-based signature matching.

### Manual gcc link (if auto-link fails)

```bash
# In the compiler/ directory:
python compiler.py ../scripts/proc_scanner.jk
gcc output/proc_scanner.o stdlib/forensics.o -o output/proc_scanner.exe -mconsole
```

---

## 11. JOCKY Language Reference

### Types

| JOCKY type | C equivalent | Notes |
|---|---|---|
| `num` | `int64_t` | 64-bit signed integer |
| `dec` | `double` | 64-bit float |
| `text` | `const char*` | Backtick string literal |
| `flag` | `bool` | `yes` = true, `no` = false |
| `raw` | `void*` | Opaque pointer from stdlib |
| `nothing` | `void` | Return type only |

### Variables

```jocky
var name : type := expression    ## declare (always needs initializer)
name <- expression               ## reassign
```

### Functions

```jocky
func name(param1 : type1, param2 : type2) -> return_type {
    ## body
    give value    ## return with value
    give          ## void return
}
```

### Control flow

```jocky
## if / else
check (condition) {
    ## then branch
} otherwise {
    ## else branch (optional)
}

## while loop
loop (condition) {
    ## body
    stop   ## break
    skip   ## continue
}
```

### Operators

| Operator | Type | Meaning |
|---|---|---|
| `+` `-` `*` `/` `mod` | Arithmetic | Standard math |
| `is` `isnt` | Comparison | Equal / not equal (works on text with strcmp) |
| `gt` `lt` `gte` `lte` | Comparison | Numeric ordering |
| `also` | Logical | AND (no short-circuit) |
| `or` | Logical | OR (no short-circuit) |
| `flip` | Logical | NOT |
| `:=` | Declaration | Assign on declare |
| `<-` | Assignment | Reassign existing variable |
| `->` | Syntax | Return type arrow in function header |

### Literals

```jocky
42          ## num literal
3.14        ## dec literal
`hello`     ## text literal (backtick-delimited)
yes         ## flag true
no          ## flag false
empty       ## null pointer (raw type)
```

### Comments

```jocky
## Single-line only — from ## to end of line
```

### Standard library

```jocky
report(msg : text)                    ## print [JOCKY] msg to stdout

procs_list() -> raw                   ## enumerate running processes
proc_count(procs : raw) -> num        ## count processes
proc_name(procs : raw, i : num) -> text   ## process name at index i
proc_pid(procs : raw, i : num) -> num     ## PID at index i
proc_kill(pid : num)                  ## terminate process by PID
proc_mem_read(pid : num, addr : num, size : num) -> raw  ## read process memory

net_conns() -> raw                    ## snapshot of TCP/UDP connections
net_sniff(duration_ms : num) -> raw   ## passive packet capture

reg_read(key : text, value : text) -> text   ## read registry value
reg_list(key : text) -> raw                  ## list registry subkeys

file_list(path : text) -> raw         ## list directory contents
file_read(path : text) -> raw         ## read file into buffer

sys_info() -> raw                     ## system information
hash_file(path : text) -> raw         ## SHA-256 of a file (32 bytes)
```

### Complete example

```jocky
## Full example: scan processes and report suspicious ones

func check_process(name : text) -> nothing {
    check (name is `mimikatz.exe`) {
        report(`[CRITICAL] Credential dumper detected!`)
    }
    check (name is `nc.exe`) {
        report(`[HIGH] Netcat backdoor found!`)
    }
}

func start() -> nothing {
    report(`Starting process scan...`)

    var procs : raw := procs_list()
    var count : num := proc_count(procs)
    var i : num := 0

    loop (i lt count) {
        var name : text := proc_name(procs, i)
        report(name)
        check_process(name)
        i <- i + 1
    }

    report(`Scan complete.`)
}
```

---

## 12. Troubleshooting

### `ModuleNotFoundError: No module named 'llvmlite'`

```bash
pip install llvmlite
```

If pip install fails on Windows, download the wheel from:  
https://github.com/numba/llvmlite/releases

### `ERROR: gcc not found`

Install MinGW (Windows) or gcc (Linux/macOS).  
JIT mode (`jocky run`) works **without** gcc — only native binary output needs it.

### `llvmlite` version conflict

```bash
pip install "llvmlite>=0.39.0" --upgrade
```

### Rich not displaying colours on Windows

Enable VT100 in cmd.exe:
```bat
reg add HKCU\Console /v VirtualTerminalLevel /t REG_DWORD /d 1
```
Or use Windows Terminal instead of cmd.exe.

### Script runs but output looks wrong

Make sure the script has `func start() -> nothing { ... }` — it's mandatory.

### `Parse error` on valid-looking code

Check that:
- Strings use backticks `` ` `` not quotes `"` or `'`
- Every `var` has `:=` initializer
- `check`/`loop`/`func` bodies are wrapped in `{ }`
- Comments start with `##` not `#`

### Build produces `.o` but no `.exe`

Run `setup.bat` first to build `forensics.o`. Then rebuild:
```bash
jocky build scripts/proc_scanner.jk
```

### `forensics.o` build fails

Ensure gcc is properly installed and on PATH:
```bash
gcc --version   # should print version info
python compiler/build_stdlib.py
```

---

*JOCKY — Built for Smart India Hackathon (SIH) · LLVM-powered · AV evasion research*
