# jockyrt dump format (`.jkd`)

The container `jkf_dump_open_write` / `jkf_dump_put` / `jkf_dump_close` produce
and `jkf_dump_open_read` consumes. Deliberately simple: a JOCKY scanner
(`jocky-mem scan-dump`, F.9) reopens it offline, with the target gone, and
rebuilds the region inventory byte-for-byte.

Format version **1** (`JKF_DUMP_FORMAT_VERSION`). Full-fidelity minidump output
is a separate, later thing.

## Layout

    +--------------------------------------------------+  file offset 0
    | JkfDumpHeader                        128 bytes   |
    +--------------------------------------------------+
    | JkfDumpRegionEntry #0                 32 bytes   |
    | region #0 raw bytes                blobLen bytes |
    +--------------------------------------------------+
    | JkfDumpRegionEntry #1                            |
    | region #1 raw bytes                              |
    +--------------------------------------------------+
    | ...  (regionCount entries total)                 |
    +--------------------------------------------------+

Each entry is immediately followed by its blob, so the file is written in one
forward pass. `jkf_dump_open_read` walks the entries once to build an in-memory
index, then `jkf_dump_region` / `jkf_dump_read` are O(1).

## JkfDumpHeader — 128 bytes

| offset | size | field            | notes                                     |
|-------:|-----:|------------------|-------------------------------------------|
| 0      | 8    | `magic`          | `"JKYDUMP\0"` (7 chars + NUL)             |
| 8      | 4    | `formatVersion`  | 1                                         |
| 12     | 4    | `headerSize`     | 128                                       |
| 16     | 4    | `targetPid`      |                                           |
| 20     | 4    | `regionCount`    | written by `jkf_dump_close`               |
| 24     | 8    | `timestamp`      | Windows `FILETIME` at `jkf_dump_open_write` |
| 32     | 8    | `totalBlobBytes` | sum of `blobLen`; written by `jkf_dump_close` |
| 40     | 72   | `imageName`      | target main-image basename, UTF-8, NUL-padded |
| 112    | 16   | `reserved`       | 0                                         |

## JkfDumpRegionEntry — 32 bytes

| offset | size | field     | notes                                            |
|-------:|-----:|-----------|--------------------------------------------------|
| 0      | 4    | `version` | `JKF_DUMP_ENTRY_VERSION` (1)                     |
| 4      | 4    | `meta`    | caller tag - the forensic dumper uses it for the per-region read status (0 full, 1 partial, 2 unreadable) |
| 8      | 8    | `base`    | region base address in the (now gone) target    |
| 16     | 8    | `size`    | the region's full size                          |
| 24     | 8    | `blobLen` | bytes stored right after this entry; `0` for an unreadable region, and may be `< size` on a partial read |

Multi-byte fields are little-endian.
