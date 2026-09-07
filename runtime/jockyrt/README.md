# jockyrt

The JOCKY forensic runtime shim: a small C11 static library that keeps the
Win32/NT structs, handle lifetimes, and Unicode paths out of JOCKY. It is
linked into forensic builds (Part 3 of `docs/requirements.md`).

- **`include/jockyrt.h`** — the whole public surface. Every function follows the
  flat ABI: scalars in, records written into caller buffers, `< 0` is
  `-(error)`.
- **`abi.md`** — the normative record layouts (offsets, sizes, `flags` bits) a
  JOCKY `struct` overlay must match.
- **`dump-format.md`** — the `.jkd` dump container's on-disk layout (R.9).
- **`src/`** — one file per area (`process.c`, `privilege.c`, `error.c`, ...).
- **`test/smoke.c`** — a ctest-registered self-check against the live machine.

## Build & test

Built as part of the top-level CMake project (`add_subdirectory(runtime/jockyrt)`).

    cmake --build build --target jockyrt          # the library
    cmake --build build --target check-jockyrt    # build + run the smoke test
    ctest --test-dir build -R jockyrt             # just the test

## Status

Implemented: R.1–R.7 and R.9 (`jkf_dump_*`, format in `dump-format.md`).

Not yet: R.8 (`PssCaptureSnapshot`, a SHOULD).

## Platforms

Windows x64 only. On other platforms every `jkf_*` call returns
`JKF_E_UNSUPPORTED` so the library still compiles.
