# JOCKY Framework

## What It Is

JOCKY is a Windows-first kernel security research platform. It combines four subsystems into one tool: a compiled domain-specific language (`.jk`), a BYOVD (Bring Your Own Vulnerable Driver) kernel engine, a user-mode evasion toolkit, and a C2 (command-and-control) framework.

The goal is a single, integrated environment for writing, compiling, and running security research tools that span the full privilege stack — from user-mode process manipulation up to ring-0 kernel operations — without depending on a patchwork of external utilities.

## Why It Exists

Most security research workflows duct-tape together a mix of scripting languages, compiled payloads, and standalone tools that were never designed to work together. JOCKY treats the research environment itself as a first-class engineering problem:

- **The `.jk` language** gives you a compiled, strongly-typed language that emits native Windows executables via LLVM. Every binary is polymorphic by construction: different SHA-256, encrypted strings, injected dead-code paths. You write it once; the toolchain makes it evasive automatically.
- **The BYOVD engine** provides kernel read/write without writing a kernel driver. It loads a known-vulnerable signed driver (RTCore64.sys, CVE-2019-16098) that exposes an IOCTL interface, then uses that interface to read arbitrary kernel memory, enumerate process-notification callbacks, and null out EDR entries.
- **The evasion module** covers the user-mode attack surface: restoring hooked API functions from disk, issuing system calls directly (bypassing ntdll hooks), injecting DLLs, hollowing processes, and redirecting thread execution.
- **The C2 module** provides an asyncio multi-agent server, an auto-reconnecting agent that can receive and JIT-execute `.jk` scripts remotely, and a domain-fronting transport that routes C2 traffic through a CDN edge node to obscure the real server.

## Platform

| Feature | Windows | Linux |
|---|---|---|
| `.jk` compiler (JIT + native) | Full | Full |
| BYOVD / kernel operations | Full | Stub (process/net scanning only) |
| Evasion modules | Full (Win32/ntdll) | Not available |
| C2 server + agent | Full | Full |
| Pre-built scripts | Full | Partial |

All evasion modules raise `ImportError` on non-Windows. BYOVD falls back to simulation mode on Linux.

## Architecture

```
jocky.py (CLI)          jocky_terminal.py (TUI)
       │                          │
       └──────────┬───────────────┘
                  │
          compiler/compiler.py
          ┌───────┴──────────────────────┐
          │  lexer → parser → semantic   │
          │  codegen → obfuscation passes│
          │  stdlib (JIT bridge)         │
          └───────┬──────────────────────┘
                  │ JIT calls into ──────────────────────┐
                  │                                      │
           byovd/                                  evasion/
           ├── loader.py      (DriverLoader)        ├── api_unhook.py
           ├── kernel.py      (KernelOps/Interface) ├── syscall.py
           ├── scanner.py     (DriverScanner)       ├── inject.py
           └── db/loldrivers.json                   ├── hollow.py
                                                    └── thread_hijack.py

           c2/
           ├── server.py      (C2Server / AgentSession)
           ├── agent.py       (C2Agent)  ← imports compiler
           └── fronting.py    (FrontedTransport / SOCKS5)
```

Key integration points:

- `compiler/jocky/stdlib.py` is the bridge between the JIT runtime and the BYOVD/kernel packages. When a `.jk` script calls `byovd_scan()` or `kernel_base()`, stdlib.py lazily initialises `DriverScanner` or `KernelInterface` and delegates.
- `c2/agent.py` imports the compiler. When the C2 server sends an `exec_code` command, the agent writes the JOCKY source to a temp file and calls `compile_jocky(..., run_jit=True)`.
- Native (`.exe`) builds use `compiler/stdlib/forensics.c` instead of `stdlib.py`. The C implementation handles string XOR-decryption at runtime using the `_jocky_xor_key` global that the obfuscation pass embeds in every binary.

## Entry Points

| Entry point | Purpose |
|---|---|
| `jocky.py` | CLI dispatcher — `run`, `build`, `ir`, `tokens`, `ast`, `inspect`, `byovd` subcommands |
| `jocky_terminal.py` | Interactive Rich-based TUI covering all subsystems |
| `jocky.bat` / `jocky.sh` | OS-native launchers that forward to `jocky.py` |
| `setup.bat` / `setup.sh` | First-run setup: `pip install -r requirements.txt` + MinGW location |

## Module Documentation

| Module | Doc |
|---|---|
| Compiler + `.jk` language | [docs/compiler/overview.md](compiler/overview.md) |
| `.jk` language reference | [docs/compiler/language-reference.md](compiler/language-reference.md) |
| Obfuscation pipeline | [docs/compiler/obfuscation.md](compiler/obfuscation.md) |
| BYOVD engine | [docs/byovd/overview.md](byovd/overview.md) |
| BYOVD API reference | [docs/byovd/api-reference.md](byovd/api-reference.md) |
| Evasion toolkit | [docs/evasion/overview.md](evasion/overview.md) |
| Evasion API reference | [docs/evasion/api-reference.md](evasion/api-reference.md) |
| C2 framework | [docs/c2/overview.md](c2/overview.md) |
| C2 API reference | [docs/c2/api-reference.md](c2/api-reference.md) |
| Pre-built scripts | [docs/scripts/overview.md](scripts/overview.md) |
