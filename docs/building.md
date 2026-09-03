# Building JOCKY

## What you need

- **Windows 11** with **Visual Studio 2022 Build Tools** (the "Desktop
  development with C++" workload). This provides `cl.exe`, `link.exe`, and the
  Windows SDK.
- **CMake 3.20+** and **Ninja**.
- **Python 3** (only used to run the test suite).
- An **LLVM 18 development SDK**. `scripts/bootstrap.ps1` sets one up under
  `.vendor/` for you.

## First-time setup

From an **elevated** PowerShell prompt (it installs system packages):

    .\scripts\bootstrap.ps1

This installs the system dependencies, provisions the LLVM SDK, writes
`.jocky-env.ps1` with the environment variables the build needs, and runs the
first CMake configure.

## Everyday build

From a normal shell:

    . .\.jocky-env.ps1                       # load the env vars
    .\scripts\bootstrap.ps1 -SkipSystemDeps  # re-configure (fast)
    cmake --build build

The `jocky` executable lands in `build\bin\jocky.exe`.

### Configuring by hand

If you would rather not use the bootstrap script, configure from a shell that
already has the MSVC environment (a "Developer PowerShell for VS 2022", or an
"x64 Native Tools Command Prompt") and `ninja` on `PATH`:

    cmake --preset default
    cmake --build build

`CMakePresets.json` pins the Ninja generator, the vendored LLVM SDK, and the
vcpkg toolchain.

## Common Windows errors

**`LNK2038: mismatch detected for '_ITERATOR_DEBUG_LEVEL'` / `'RuntimeLibrary'`**
The vendored LLVM is a Release build and uses the release C runtime. Our code
must use the same one. `cmake/jocky_llvm.cmake` pins
`CMAKE_MSVC_RUNTIME_LIBRARY` to `MultiThreadedDLL` for every configuration to
make this match. If you see this error, your build directory is probably stale -
delete `build\` and re-configure.

**`CMAKE_MAKE_PROGRAM is not set` / "generator ... does not match"**
Ninja is not on `PATH`, or an old `build\` directory was configured with a
different generator. `bootstrap.ps1` handles both (it finds a vendored `ninja`
and discards a mismatched cache). By hand: put `ninja` on `PATH` and delete
`build\`.

**`find_package(LLVM ...)` fails**
`LLVM_DIR` is not pointing at a real SDK. The official LLVM installer and the
winget package do **not** include the development files. Use the vendored SDK
under `.vendor\llvm-install-18.1.8` (this is what `bootstrap.ps1` sets up).

**`lld-link: error: could not open 'libcmt.lib'`** when running `jocky build`
The link step could not find the MSVC / Windows SDK libraries. Run `jocky` from
a Visual Studio developer prompt, or make sure Visual Studio is installed so
`clang` can locate them itself.
