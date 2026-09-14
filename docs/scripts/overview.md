# Pre-Built Scripts

## Overview

The `scripts/` directory contains 11 `.jk` programs covering the most common security research tasks: process analysis, network monitoring, kernel reconnaissance, driver scanning, registry inspection, and file integrity. They are ready to run with `jocky run` and serve as starting points for custom scripts.

All scripts follow the same pattern: a `start()` entry point with no parameters that prints structured output to stdout.

## Running Scripts

```
jocky run scripts/<name>.jk
jocky run --kernel scripts/<name>.jk     (for kernel/BYOVD scripts)
jocky run --obfuscate scripts/<name>.jk  (with obfuscation passes)
```

From the TUI: **Scripts** menu → select by name.

---

## `proc_scanner.jk`

**Purpose:** Full process enumeration. Lists every running process with its PID, name, and security classification.

**Why use it:** Quick system survey; first step in any engagement to understand what security software is present and what users are running.

**Output:** Table of processes. Each entry is classified as `SYSTEM`, `USER`, `SECURITY` (EDR/AV), or `UNKNOWN`. Security processes are highlighted.

**Stdlib functions used:** `proc_list`, `proc_count`, `proc_classify`

---

## `kernel_recon.jk`

**Purpose:** Kernel-level reconnaissance. Resolves the ntoskrnl.exe base address and enumerates all process-notification callbacks, identifying which belong to EDR/AV products.

**Why use it:** Before any kernel operation, you need the kernel base and a map of which EDR callbacks are active. This script gives you that map without modifying anything.

**Requires:** `--kernel` flag (uses BYOVD stdlib). Runs in simulation mode if not Administrator.

**Output:** Kernel base address (hex), then a list of callbacks with index, address, owning module, and Microsoft/non-Microsoft classification.

**Stdlib functions used:** `kernel_base`, `kernel_callbacks`

---

## `byovd_scanner.jk`

**Purpose:** Scan all installed drivers against the LOLDrivers vulnerable-driver database.

**Why use it:** Checks whether the system already has a vulnerable driver loaded (meaning BYOVD is trivially available) or one present on disk (meaning it can be loaded without dropping a new file). Useful for both offensive enumeration and defensive auditing.

**Output:** Count of drivers scanned, count of vulnerable matches, then for each match: path, SHA-256, CVE, risk level, tags.

**Stdlib functions used:** `byovd_scan`

---

## `threat_hunter.jk`

**Purpose:** Combined threat hunt across four data sources: running processes, active network connections, registry autorun keys, and filesystem paths.

**Why use it:** A single script that cross-correlates process, network, and persistence indicators. Useful as a quick triage script on a suspicious host.

**Output:** Section-by-section report: suspicious processes (by name pattern), external network connections, autorun registry entries, and presence of known-malicious file paths.

**Stdlib functions used:** `proc_list`, `proc_classify`, `net_connections`, `reg_read`, `file_exists`

---

## `registry_inspector.jk`

**Purpose:** Reads and reports on key security-relevant registry locations.

**Why use it:** Registry keys control LSA protection, Defender policies, Windows Defender exclusions, and Winlogon behaviour — all common targets for persistence and defence degradation. This script gives a snapshot of their current state.

**Keys inspected:**
- `HKLM\SYSTEM\CurrentControlSet\Control\Lsa` (RunAsPPL, LimitBlankPasswordUse)
- `HKLM\SOFTWARE\Policies\Microsoft\Windows Defender` (DisableAntiSpyware, DisableRealtimeMonitoring)
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`
- `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run` (autoruns)

**Stdlib functions used:** `reg_read`, `reg_exists`

---

## `sys_info.jk`

**Purpose:** Collect basic system information: OS version, hostname, architecture, current user, uptime.

**Why use it:** First script to run on a new target for initial triage. Output feeds into engagement notes.

**Output:** Labelled key-value pairs.

**Stdlib functions used:** `sys_os`, `sys_hostname`, `sys_arch`, `sys_username`, `sys_uptime`

---

## `net_monitor.jk`

**Purpose:** Snapshot of all active TCP connections with remote addresses and owning PIDs.

**Why use it:** Identifies C2 connections, data exfiltration channels, and unexpected listening ports. Cross-reference with `proc_scanner.jk` to name the process behind each connection.

**Output:** Table of connections: local address, remote address, state, PID.

**Stdlib functions used:** `net_connections`, `net_conn_count`

---

## `net_logger.jk`

**Purpose:** Repeated network + process snapshots taken at intervals, formatted as a timeline.

**Why use it:** Captures ephemeral connections that would be missed in a single snapshot. Useful when monitoring for beaconing behaviour or watching a specific process's network activity over time.

**Output:** Timestamped connection snapshots with diffs between intervals.

**Stdlib functions used:** `net_connections`, `proc_list`, `timestamp`, `sleep_ms`

---

## `resource_monitor.jk`

**Purpose:** Detects resource-abusing processes: those with unusually high CPU time, large memory footprints, or network activity patterns consistent with miners or worms.

**Why use it:** Identifies compromised hosts running cryptominers or lateral movement tools that betray themselves through resource usage.

**Output:** Processes flagged as suspicious with their resource metrics and reason for flagging.

**Stdlib functions used:** `proc_list`, `proc_classify`, `net_find_pid`

---

## `packet_sniffer.jk`

**Purpose:** Passive network capture correlated with process information. Captures connection metadata and associates each connection with the owning process.

**Why use it:** Provides a richer view than `net_monitor.jk` by tying network activity directly to process identities — useful for identifying which process is making which connections.

**Output:** Live connection log with process names and classifications alongside connection details.

**Stdlib functions used:** `net_connections`, `net_conn_count`, `proc_name`, `proc_classify`

---

## `file_hasher.jk`

**Purpose:** Compute SHA-256 hashes of critical Windows system files and compare them against known-good values.

**Why use it:** Detects binary tampering or replacement of system files — a common persistence and rootkit technique. Also useful for verifying the integrity of files before trusting them.

**Files hashed:**
- `C:\Windows\System32\ntdll.dll`
- `C:\Windows\System32\kernel32.dll`
- `C:\Windows\System32\lsass.exe`
- `C:\Windows\System32\svchost.exe`
- Selected drivers in `System32\drivers\`

**Output:** Path, computed SHA-256, and a note if the hash differs from the embedded baseline.

**Stdlib functions used:** `file_hash`, `file_exists`

---

## Writing Your Own Scripts

Use the pre-built scripts as templates. The minimum valid script:

```jk
func start() -> nothing {
    print(`hello`)
}
```

See [docs/compiler/language-reference.md](../compiler/language-reference.md) for the full syntax and stdlib function list.

Place custom scripts in `scripts/` to make them available in the TUI, or in `workspace/` for scratch work (the TUI's editor buffer is `workspace/scratch.jk`).
