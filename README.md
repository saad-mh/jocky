# JOCKY

JOCKY is a small compiled programming language. Its compiler is written in C++
and uses LLVM to turn `.jk` source files into native executables.

    hello.jk  ->  lexer  ->  parser  ->  AST  ->  LLVM IR  ->  object file  ->  native executable

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
.\build\bin\jocky.exe build --emit-llvm <file>.jk     # print the LLVM IR
.\build\bin\jocky.exe lex   --dump-tokens <file>.jk   # print the token stream
.\build\bin\jocky.exe parse --dump-ast    <file>.jk   # print the syntax tree
```

## Tests

```powershell
cmake --build build --target check     # LLVM lit + FileCheck suite
```

See [docs/testing.md](docs/testing.md).

## The language (v0)

64-bit integers, string literals, variables, functions, `if` / `else`, `while`,
arithmetic and comparison operators, and a `print` builtin. Top-level statements
run as an implicit `main`. Every function parameter and return value is a 64-bit
integer. A string literal may only be passed directly to `print`.

The full grammar is in [docs/grammar.md](docs/grammar.md). The compiler's
internal structure is in [docs/architecture.md](docs/architecture.md), and the
extension point for future code-generation passes is described in
[docs/codegen-and-passes.md](docs/codegen-and-passes.md).
