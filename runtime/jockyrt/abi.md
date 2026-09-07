# jockyrt ABI

The contract between `jockyrt` (C) and the JOCKY forensic code. This file is
normative: a JOCKY `struct` overlaid on a record buffer must match the offsets
here exactly. `include/jockyrt.h` carries the same layouts as C structs and a
`_Static_assert` on each size.

Current ABI version: **1** (`jkf_abi_version()` / `JKF_ABI_VERSION`).

## Rules (requirement R.1)

- No C `struct` is ever an argument or a return value. Every `jkf_*` function
  takes scalars (`int32`, `uint32`, `uint64`, `bool`) and, where it produces
  variable data, a caller-owned buffer as `void* out` plus a `uint64` byte
  capacity.
- Every record the shim writes begins with a `uint32 version` field equal to
  the matching `JKF_*_RECORD_VERSION`. Consumers check it before trusting the
  rest.
- Records use natural alignment with fields ordered so there is no interior
  padding; any tail padding to the record's alignment is called out below.
- Multi-byte fields are little-endian (the only supported target is x64
  Windows).

## Return convention

A `jkf_*` function returns an `int32`:

| value  | meaning                                                        |
|--------|--------------------------------------------------------------- |
| `>= 0` | success - a count, a length in bytes, or a handle-ish token   |
| `< 0`  | `-(error)`, one of the `JKF_E_*` codes                        |

`JKF_E_*`:

| name              | value | meaning                                          |
|-------------------|-------|--------------------------------------------------|
| `JKF_OK`          |  0    | success                                          |
| `JKF_E_INVAL`     | -1    | a bad argument (null buffer, zero length, ...)   |
| `JKF_E_TOOSMALL`  | -2    | the buffer cannot hold the result; call the matching `*_count` |
| `JKF_E_FAULT`     | -3    | the whole address range is unreadable            |
| `JKF_E_ACCESS`    | -4    | access denied / insufficient privilege           |
| `JKF_E_NOTFOUND`  | -5    | no such pid / region / module / thread           |
| `JKF_E_BADHANDLE` | -6    | not a handle this shim handed out                |
| `JKF_E_OS`        | -7    | an OS call failed; `jkf_last_os_error()` has the `GetLastError()` |
| `JKF_E_NOMEM`     | -8    | allocation failure inside the shim               |
| `JKF_E_UNSUPPORTED`| -9   | not available on this OS / build                 |

`jkf_last_os_error()` is thread-local and only meaningful immediately after a
call returned `JKF_E_OS`.

## Records

### JkfProcessRecord — 20 bytes, 4-byte aligned (R.2)

| offset | size | field       | notes                                            |
|-------:|-----:|-------------|--------------------------------------------------|
| 0      | 4    | `version`   | `JKF_PROCESS_RECORD_VERSION` (1)                 |
| 4      | 4    | `pid`       |                                                  |
| 8      | 4    | `ppid`      | parent pid; may name a since-exited process     |
| 12     | 4    | `sessionId` |                                                  |
| 16     | 4    | `flags`     | bitset, below                                    |

`flags`:

| bit | name                     | meaning                                     |
|----:|--------------------------|---------------------------------------------|
| 0   | `JKF_PROC_WOW64`         | a 32-bit process on 64-bit Windows          |
| 1   | `JKF_PROC_PROTECTED`     | a PPL / protected process (not yet set)     |
| 2   | `JKF_PROC_ELEVATION_UNK` | elevation was not determined (always set for now) |

`jkf_processes` writes these ascending by `pid`. `jkf_process_count()` returns
how many the next call would write.

### JkfAccessRecord — 16 bytes, 4-byte aligned (R.3)

Written by `jkf_open` into its optional `accessOut` buffer.

| offset | size | field         | notes                                        |
|-------:|-----:|---------------|----------------------------------------------|
| 0      | 4    | `version`     | `JKF_ACCESS_RECORD_VERSION` (1)              |
| 4      | 4    | `level`       | `JKF_ACCESS_*` (NONE 0, QUERY 1, READ 2, READ_WRITE 3) |
| 8      | 4    | `grantedMask` | the Win32 `PROCESS_*` mask the open succeeded with |
| 12     | 4    | `reserved`    | 0                                            |

`level == JKF_ACCESS_QUERY` means headers and the region walk work but
`jkf_read` will return `JKF_E_FAULT` / `JKF_E_OS` - "queried headers only".

### JkfRegionRecord — 48 bytes, 8-byte aligned (R.4)

Written by `jkf_region_at`. The `state` / `type` / `protect` values are the raw
Win32 `MEM_*` / `PAGE_*` constants (not re-encoded).

| offset | size | field          | notes                                       |
|-------:|-----:|----------------|---------------------------------------------|
| 0      | 4    | `version`      | `JKF_REGION_RECORD_VERSION` (1)             |
| 4      | 4    | `state`        | `MEM_COMMIT` 0x1000 / `MEM_RESERVE` 0x2000 / `MEM_FREE` 0x10000 |
| 8      | 4    | `type`         | `MEM_IMAGE` 0x1000000 / `MEM_MAPPED` 0x40000 / `MEM_PRIVATE` 0x20000; 0 when free |
| 12     | 4    | `protect`      | current `PAGE_*`                            |
| 16     | 4    | `allocProtect` | `PAGE_*` at reservation (0 when free)       |
| 20     | 4    | `reserved`     | 0                                           |
| 24     | 8    | `base`         | region base address                         |
| 32     | 8    | `size`         | region size in bytes                        |
| 40     | 8    | `allocBase`    | the reservation this region belongs to (0 when free) |

`jkf_region_at` returns `1` with a record, `0` past the end of the user address
space. The caller advances `addr = base + size`; the sequence is strictly
increasing and gap-free over the whole range.

## Functions so far

| function                        | requirement | notes                          |
|---------------------------------|-------------|--------------------------------|
| `jkf_abi_version`               | R.1         | returns `JKF_ABI_VERSION`      |
| `jkf_last_os_error`             | R.1         | thread-local; valid after `JKF_E_OS` |
| `jkf_process_count`             | R.2         |                                |
| `jkf_processes`                 | R.2         | ascending by pid               |
| `jkf_enable_debug_privilege`    | R.3         | `1` held / `0` not / `<0` OS error |
| `jkf_open` / `jkf_close`        | R.3         | small-int token, not a HANDLE  |
| `jkf_region_at`                 | R.4         |                                |
| `jkf_read`                      | R.5         | chunked, guard-aware, `< len` on partial |

## Records still to come

`JkfModuleRecord` (R.6), `JkfThreadRecord` (R.7), and the dump container header
/ region table (R.9, spelled out in `dump-format.md`). Their
`JKF_*_RECORD_VERSION` constants already exist in the header at value 1.
