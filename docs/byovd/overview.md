# BYOVD Engine — Overview

## Why BYOVD

Modern EDR and AV products protect themselves by registering kernel callbacks: functions that the Windows kernel calls when a process is created, a thread starts, or an image is mapped. From user mode there is no way to remove these callbacks — they live in kernel memory and can only be modified with ring-0 write access.

BYOVD (Bring Your Own Vulnerable Driver) is the standard technique for obtaining that access without writing a kernel driver from scratch. The approach: load a legitimate, Microsoft-signed driver that was shipped with a vulnerability allowing arbitrary kernel read/write via its IOCTL interface. Because the driver is signed, Windows will load it. Once loaded, you control kernel memory.

JOCKY uses **RTCore64.sys** (CVE-2019-16098), a driver shipped with MSI Afterburner that exposes kernel read/write IOCTLs to any user-mode caller without privilege checks.

## What the BYOVD Engine Does

The BYOVD module provides four capabilities:

1. **Driver loading and IOCTL interface** — Loads RTCore64.sys as a Windows service, opens a device handle, and provides raw `read`/`write` IOCTL wrappers.

2. **Kernel operations** — Resolves the ntoskrnl.exe base address, reads/writes arbitrary kernel memory by address, enumerates `PspCreateProcessNotifyRoutine` (the array of EDR process-creation callbacks), and can null out non-Microsoft entries (blinding EDR at ring 0).

3. **EPROCESS manipulation** — Walks the kernel's `EPROCESS` doubly-linked list to find arbitrary processes by PID and supports token stealing (copying a SYSTEM token into a target process for privilege escalation).

4. **Vulnerable driver scanner** — Scans the local system's driver directories against a bundled LOLDrivers database (SHA-256 and filename), reporting which vulnerable drivers are already installed.

## Privilege and Safety Model

| Mode | When used | What happens |
|---|---|---|
| Real mode | Running as Administrator with RTCore64.sys present | Actual kernel read/write via IOCTL |
| Simulation mode | Non-admin, or explicit `simulate=True` | All operations print `[BYOVD/SIM]` and return plausible fake data |

The `simulate=True` mode exists so the rest of the framework (TUI, scripts, tests) can call BYOVD functions on any machine without crashing. It is the default when `DriverLoader.check_privileges()` returns `False`.

**Important:** Loading RTCore64.sys and patching kernel callbacks is a destructive, hard-to-reverse operation. In a real engagement, always run in a VM. The simulation mode is available for all development and testing work.

## Architecture

```
KernelInterface (high-level facade)
        │
        ▼
  KernelOps (low-level ring-0 operations)
        │
        ▼
  DriverLoader (RTCore64.sys lifecycle)
        │  IOCTL 0x80002048 (read)
        │  IOCTL 0x8000204C (write)
        ▼
  RTCore64.sys (in kernel)
        │
        ▼
  Physical kernel memory

DriverScanner (independent — no DriverLoader dependency)
        │
        ▼
  byovd/db/loldrivers.json
```

## Source Files

| File | Role |
|---|---|
| `byovd/loader.py` | `DriverLoader` — RTCore64 service install, IOCTL wrapper |
| `byovd/kernel.py` | `KernelOps` + `KernelInterface` — kernel memory and callback operations |
| `byovd/scanner.py` | `DriverScanner` — local driver scan against LOLDrivers DB |
| `byovd/db/loldrivers.json` | 40+ entries: Name, Vendor, CVE, Tags, known SHA-256 samples |
| `byovd/__init__.py` | Package exports |

## CLI Commands

```
jocky byovd scan          Scan installed drivers against the LOLDrivers DB
jocky byovd drivers       List all entries in the bundled LOLDrivers database
jocky byovd load <path>   Load a driver by path (requires Admin)
jocky byovd kernel-demo   Demonstrate kernel base resolution, callbacks, read
jocky byovd blind-edr     Enumerate callbacks and null non-Microsoft entries
```

All BYOVD operations fall back to simulation mode automatically when not running as Administrator.

## Integration with the Compiler

In JIT mode, `.jk` scripts can call BYOVD stdlib functions directly:

```jk
func start() -> nothing {
    var base : num := kernel_base()
    print_hex(base)
    var n : num := byovd_scan()
    print_num(n)
    print(` vulnerable driver(s) found`)
}
```

`jocky run --kernel scripts/kernel_recon.jk` enables the kernel-mode stdlib bridge in `compiler/jocky/stdlib.py`, which lazily initialises `KernelInterface` and `DriverScanner` when the first BYOVD function is called.

## LOLDrivers Database

`byovd/db/loldrivers.json` contains 40+ entries. Each entry has:

```json
{
  "Name": "RTCore64.sys",
  "Vendor": "Micro-Star International",
  "CVE": "CVE-2019-16098",
  "Tags": ["Kernel-RW", "EDR-Bypass", "BYOVD"],
  "Description": "MSI Afterburner driver — arbitrary kernel read/write via IOCTL",
  "KnownVulnerableSamples": [
    { "SHA256": "01aa278b07b58dc46c84bd0b1b5c8e9ee4e62ea0bf7a695862444af32e87f1fd" }
  ]
}
```

Risk scoring by tag:

| Tag | Score | Label |
|---|---|---|
| `Kernel-RW` | 10 | CRITICAL |
| `AV-Kill` | 10 | CRITICAL |
| `EDR-Bypass` | 9 | HIGH |
| `Kernel-Read` | 7 | HIGH |
| Other | ≤5 | MEDIUM / LOW |
