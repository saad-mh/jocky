# JOCKY

JOCKY is a small compiled programming language. Its compiler is written in C++
and uses LLVM to turn `.jky` source files into native executables.

    hello.jky  ->  lexer  ->  parser  ->  AST  ->  LLVM IR  ->  object file  ->  native executable

This repository is in early development. The compiler pipeline is being built up
one stage at a time; see `docs/` (added as the stages land) and the plan notes
for the current state.

## Building

You need Windows 11 with Visual Studio 2022 Build Tools (the C++ workload),
CMake 3.20+, Ninja, and Python 3. The `scripts/bootstrap.ps1` script provisions
the rest, including a vendored LLVM 18 SDK under `.vendor/`.

```powershell
# From an elevated PowerShell prompt, the first time:
.\scripts\bootstrap.ps1

# After that, from a normal shell:
. .\.jocky-env.ps1
.\scripts\bootstrap.ps1 -SkipSystemDeps    # re-configure only
cmake --build build
```

The `jocky` executable is written to `build/bin/jocky.exe`.

To configure by hand instead (from a shell that already has the MSVC x64
environment and `ninja` on `PATH`):

```powershell
cmake --preset default
cmake --build build
```

## Running

```powershell
.\build\bin\jocky.exe --version
.\build\bin\jocky.exe build examples\hello.jky -o hello.exe
.\hello.exe
```

## Tests

```powershell
cmake --build build --target check      # runs the lit + FileCheck test suite
```

## Language (v0)

64-bit integers, string literals, variables, functions, `if` / `else`, `while`,
arithmetic and comparison operators, and a `print` builtin. Top-level statements
run as an implicit `main`. String literals may only be passed directly to
`print`. See `docs/03-language-v0.md` for the full grammar.
