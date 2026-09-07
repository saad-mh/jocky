# jockyrt

The JOCKY forensic runtime shim: a small C11 static library that keeps the
Win32/NT structs, handle lifetimes, and Unicode paths out of JOCKY. It is
linked into forensic builds (Part 3 of `docs/requirements.md`).

- **`include/jockyrt.h`** — the whole public surface. Every function follows the
  flat ABI: scalars in, records written into caller buffers, `< 0` is
  `-(error)`.
- **`abi.md`** — the normative record layouts (offsets, sizes, `flags` bits) a
  JOCKY `struct` overlay must match.
- **`src/`** — one file per area (`process.c`, `privilege.c`, `error.c`, ...).
- **`test/smoke.c`** — a ctest-registered self-check against the live machine.

## Build & test

Built as part of the top-level CMake project (`add_subdirectory(runtime/jockyrt)`).

    cmake --build build --target jockyrt          # the library
    cmake --build build --target check-jockyrt    # build + run the smoke test
    ctest --test-dir build -R jockyrt             # just the test

## Status

Implemented: R.1 (flat ABI), R.2 (`jkf_processes`), R.3
(`jkf_enable_debug_privilege`, `jkf_open` / `jkf_close`), R.4
(`jkf_region_at`), R.5 (`jkf_read`), R.6 (`jkf_modules`, `jkf_mapped_name`),
R.7 (`jkf_threads`).

Next: R.9 dump container, R.8 snapshot.

## Platforms

Windows x64 only. On other platforms every `jkf_*` call returns
`JKF_E_UNSUPPORTED` so the library still compiles.
