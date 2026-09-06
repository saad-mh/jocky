# JOCKY

JOCKY is a small compiled programming language. Its compiler is written in C++
and uses LLVM to turn `.jk` source files into native executables.

    hello.jk  ->  lexer  ->  parser  ->  AST  ->  sema  ->  LLVM IR  ->  object file  ->  native executable

## Example

`examples/hello.jk`:

```
print("hello, world");
```

```powershell
.\build\bin\jocky.exe build examples\hello.jk -o hello.exe
.\hello.exe            # prints: hello, world
```

A slightly bigger one, `examples/fib.jk`:

```
func fib(n) {
    if (n < 2) {
        return n;
    }
    return fib(n - 1) + fib(n - 2);
}

print(fib(10));         // prints: 55, hopefully
```

## Building

See [docs/building.md](docs/building.md). In short: run `scripts\bootstrap.ps1`
once (it provisions a vendored LLVM 18 SDK under `.vendor/`), then
`cmake --build build`.

## Running a program

```powershell
.\build\bin\jocky.exe build <file>.jk -o <file>.exe   # compile and link
.\build\bin\jocky.exe build <file>.jk -l ntdll -L C:\libs   # extra link inputs
.\build\bin\jocky.exe build --emit-llvm <file>.jk     # print the LLVM IR
.\build\bin\jocky.exe build --obfuscate <file>.jk -o <file>.exe   # + obfuscation passes
.\build\bin\jocky.exe check <file>.jk                 # front end + semantic analysis only
.\build\bin\jocky.exe lex   --dump-tokens <file>.jk   # print the token stream
.\build\bin\jocky.exe parse --dump-ast    <file>.jk   # print the syntax tree
```

`--obfuscate` (add `--obf-seed <n>` for a reproducible build) runs JOCKY's own
IR transform passes; see [docs/codegen-and-passes.md](docs/codegen-and-passes.md).

## Tests

```powershell
cmake --build build --target check     # LLVM lit + FileCheck suite
```

See [docs/testing.md](docs/testing.md).

## The language

A small static type system - `int` (64-bit, the default), `char` (`u8`, the
byte type), `bool`, `double` / `float`, and the sized aliases `i8`..`i64` /
`u8`..`u64` - with literals (`0x2A`, `42u32`, `3.14f`, `'A'`, `true`), `expr as
T` casts, widening-only implicit conversions, and type-directed `print`.
Fixed arrays `T[N]` and borrowed slices `T[]` (`arr[i]`, `arr[a:b]`, `arr.len`,
`[1, 2, 3]`); a string literal is a NUL-terminated `char[]`. Functions annotate
their parameters (`func f(a: int) -> bool`); locals infer their type.
Variables, `if` / `else`, `while`, arithmetic / comparison / cast operators.
Top-level statements run as an implicit `main`.

The full grammar is in [docs/grammar.md](docs/grammar.md). The compiler's
internal structure is in [docs/architecture.md](docs/architecture.md), and the
extension point for future code-generation passes is described in
[docs/codegen-and-passes.md](docs/codegen-and-passes.md).

Planned language extensions - a static type system, low-level and FFI
primitives - and the memory-forensics tool they exist to support are specified
in [docs/requirements.md](docs/requirements.md).
