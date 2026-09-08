# Baseline Hash DB Format (F.9)

## Overview

The baseline hash DB (`JkfBaseline*`) is a binary format for storing per-page hashes of module `.text` sections to support image-tampering detection (F.5.6) and baseline construction (F.9).

Layout: fixed binary records, magic, static-asserted sizes, deterministic order (ascending module name, ascending page offset within each module).

## File Layout

```
[JkfBaselineHeader]                                    (64 bytes, offset 0)
  repeated moduleCount times:
    [JkfBaselineModuleEntry]                           (80 bytes per module)
    [JkfBaselinePageEntry] × pageCount_of_this_module  (16 bytes per page)
```

Total file size: `64 + sum(80 + 16*pageCount[i] for each module i)`

## Structures

### JkfBaselineHeader (64 bytes)

| Offset | Size | Field | Meaning |
|--------|------|-------|---------|
| 0 | 8 | `magic[8]` | ASCII `"JKYBASE\0"` — file magic, NUL-padded |
| 8 | 4 | `formatVersion` | Version of this format (currently `1`) |
| 12 | 4 | `headerSize` | Size of this header in bytes (`64`) |
| 16 | 4 | `moduleCount` | Number of modules in this baseline (filled at close) |
| 20 | 4 | `pageCount` | Total number of pages across all modules (filled at close) |
| 24 | 8 | `timestamp` | Windows FILETIME (100ns ticks since 1601 UTC) of creation |
| 32 | 32 | `reserved` | Unused; zeroed on write, ignored on read |

**Version history:**
- `1` — Initial format (present)

### JkfBaselineModuleEntry (80 bytes per module)

Immediately follows the header; one entry per loaded module during `baseline build`.

| Offset | Size | Field | Meaning |
|--------|------|-------|---------|
| 0 | 4 | `version` | Version of this entry format (currently `1`) |
| 4 | 4 | `pageCount` | Number of pages this module has (follows immediately in file) |
| 8 | 8 | `preferredBase` | `ImageBase` (preferred load address) from the module's PE header (informational) |
| 16 | 64 | `name[64]` | Module basename (e.g., `"kernel32.dll"`), UTF-8, NUL-padded, left-aligned |

**Order:** Modules appear in the order they were recorded by `jkf_baseline_put_module()` calls. In a baseline built by `baseline build --pid <p>` which walks `jkf_modules()`, this is the order returned by the kernel (typically ascending by load address but unspecified).

### JkfBaselinePageEntry (16 bytes per page)

Each module entry is immediately followed by its `pageCount` page entries.

| Offset | Size | Field | Meaning |
|--------|------|-------|---------|
| 0 | 4 | `version` | Version of this entry format (currently `1`) |
| 4 | 4 | `pageOffset` | Byte offset within the module's `.text` section (multiple of 4096, 0-based) |
| 8 | 8 | `hash` | FNV-1a 64-bit hash of the normalized (ASLR-de-relocated) page bytes |

**Page order:** Within each module, pages appear in ascending `pageOffset` order (0, 4096, 8192, ...). If a module's `.text` is 10,000 bytes, two pages are stored (offset 0 and offset 4096).

## Semantics

### Writing (Append Mode)

1. Call `jkf_baseline_open_write(path, append=0)` to create a fresh baseline → writes header with counts = 0
2. Call `jkf_baseline_open_write(path, append=1)` to extend an existing baseline → reads header, appends after last module entry, skips modules whose name already exists
3. For each module to record:
   - `jkf_baseline_put_module(handle, name, preferred_base)` → appends one `JkfBaselineModuleEntry`
   - For each page in that module's `.text`:
     - `jkf_baseline_put_page(handle, offset, hash)` → appends one `JkfBaselinePageEntry`
4. `jkf_baseline_close(handle)` → patches `moduleCount` and `pageCount` into the header

Append mode enables incremental baseline building: run `baseline build --pid <p> --out db.bin` once per system process to accumulate a system-wide baseline without a directory-scan API.

### Reading

1. `jkf_baseline_open_read(path)` → reads and indexes the entire file
2. `jkf_baseline_find_page(handle, moduleName, pageOffset, hashOut, cap)` → binary search by module name (or linear if many), then by page offset within that module; returns the hash or `JKF_E_NOTFOUND`
3. `jkf_baseline_close(handle)` → frees index

## Determinism (V.6)

A baseline built from the same input (same process, same modules, same disk state) produces an identical file:
- Magic, format version, timestamp, counts are deterministic
- Module order reflects `jkf_modules()` enumeration order (kernel-defined, stable for a given snapshot)
- Page order within each module is ascending by offset (deterministic)
- Hashes are FNV-1a, deterministic on normalized bytes

Two `baseline build` runs against the same target produce byte-identical files up to the `timestamp` field (if timestamps match, byte-for-byte identical).

## Safety (V.7)

- File I/O uses `CreateFileW` with UTF-8 path conversion (no shell escaping issues)
- Module paths are read from the live target, validated by PE parsing before hashing
- Hash computation is local to the baseline-building process, no external dependencies
- Baseline DB is read-only after creation (write handles close after `jkf_baseline_close`)

## Size & Performance

For a typical Windows system:
- ~100 modules, ~10 MiB total `.text` → ~2.5K pages → ~200 KiB baseline (64B header + 100*80B entries + 2500*16B hashes)
- Write-side: sequential appends, no indexing overhead
- Read-side: one full-file read at open, then O(log M + log P) lookups per page query (M = module count, P = pages per module)
