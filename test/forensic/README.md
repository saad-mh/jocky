# Forensic Memory Tool Tests (Part 4 - V.1 to V.8)

This directory contains the validation suite for JOCKY's forensic memory module.

## Status

**V.1 - Fixture-driven detection tests**: In progress
- Harness architecture: implemented (in-process injection + scanning)
- Fixtures: F.5.1-F.5.10 skeleton implemented
- Note: Requires elevated (administrator) privileges to scan processes with full memory visibility

**V.2-V.8**: Not yet started

## Running Tests

```powershell
# Run all tests (requires elevation)
.\run.ps1

# Run specific fixture
.\run.ps1 -FixtureName f5_1_rwx -Verbose

# List available fixtures
.\run.ps1 -ListOnly
```

## Structure

- `harness-v3.ps1` — test harness (active)
- `fixtures/` — PowerShell injection scripts for each technique
- `run.ps1` — entry point

## Test Approach

V.1 uses **in-process injection**: fixtures allocate suspicious memory regions in the same PowerShell process running the harness, then `jocky-mem` scans that process. This avoids elevation requirements for the test infrastructure while validating jocky-mem's scanning capability.

However, **cross-process scanning** (separate fixture processes) requires elevation due to Windows access restrictions—jockyrt's `jkf_enable_debug_privilege()` is needed to get full memory visibility.

## Fixtures

| Fixture | F.5.x | Injection Technique |
|---------|-------|---------------------|
| `f5_1_rwx` | F.5.1 | RWX allocation; write-then-exec |
| `f5_2_exec_private` | F.5.2 | Private executable memory |
| `f5_4_pe_sig` | F.5.4 | PE header in private memory |
| `f5_6_hollow` | F.5.6 | Process hollowing (cross-process; requires elevation) |
| `f5_7_thread_anomaly` | F.5.7 | Thread with anomalous start address |
| `f5_10_single_page_exec` | F.5.10 | Single-page executable region |

Not yet implemented:
- F.5.3 (executable mapped data)
- F.5.5 (loader list mismatch)
- F.5.8 (hook detection)
- F.5.9 (entropy)

## Notes

- Tests validate that heuristics fire correctly on injected regions
- Expected findings are verified against jocky-mem's JSON or text output
- Deferred heuristics (marked SHOULD) will be added once core MUST items pass
