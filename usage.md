# JOCKY — Usage Guide

JOCKY is a compiled language that turns `.jk` source files into native Windows
executables via LLVM. The compiler binary is `build\bin\jocky.exe`.

---

## 1. Quick start

```powershell
# Compile and run
.\build\bin\jocky.exe build examples\hello.jk -o hello.exe
.\hello.exe
# hello, world
```

---

## 2. Compiler commands

| Command | What it does |
|---------|--------------|
| `build <file>.jk -o <out>.exe` | Compile + link to a native executable |
| `build --emit-llvm <file>.jk` | Print the generated LLVM IR (no output file) |
| `build --obfuscate <file>.jk -o <out>.exe` | Compile with IR obfuscation passes |
| `build --obfuscate --obf-seed <n> <file>.jk` | Reproducible obfuscated build |
| `check <file>.jk` | Run the front-end + semantic analysis only |
| `lex --dump-tokens <file>.jk` | Print the token stream |
| `parse --dump-ast <file>.jk` | Print the parsed AST |
| `build -l <name> -L <dir> <file>.jk` | Link an extra library from a directory |

---

## 3. Language in examples

### Hello, world

```jk
print("hello, world");
```

Top-level statements run as an implicit `main`. No boilerplate required.

### Variables and arithmetic

```jk
let a = 6;
let b = 7;
let sum = a + b;      // int (64-bit, the default)
print(sum);           // 13
```

### Control flow

```jk
// while + check/otherwise
let i = 1;
let total = 0;
while (i <= 10) {
    total = total + i;
    i = i + 1;
}
print(total);  // 55

let n = 5;
while (n > 0) {
    check (n % 2 == 0) { print(0); }
    otherwise             { print(1); }
    n = n - 1;
}
```

### Functions

```jk
func add(a: int, b: int) -> int {
    return a + b;
}

func square(n: int) -> int {
    return n * n;
}

print(square(add(1, 2)));  // 9
```

### Recursion

```jk
func fib(n: int) -> int {
    check (n < 2) { return n; }
    return fib(n - 1) + fib(n - 2);
}

print(fib(10));  // 55
```

### Types

```jk
let x: u32 = 42u32;       // sized unsigned integer
let c: char = 'A';        // u8 / byte
let ok: flag = yes;
let pi: double = 3.14159;
let pf: float  = 3.14f;
```

Sized integer suffixes: `i8 i16 i32 i64 u8 u16 u32 u64`.

### Arrays and slices

```jk
let arr: int[4] = [10, 20, 30, 40];
print(arr[2]);        // 30
print(arr.len);       // 4

let s: int[] = arr[1:3];   // borrowed slice of elements 1..2
print(s[0]);               // 20
print(s.len);              // 2
```

### Pointers and structs

```jk
struct Point {
    x: int,
    y: int,
}

let p: Point;
p.x = 3;
p.y = 4;

let pp: ptr<Point> = &p;
print(pp.x);              // 3 — ptr<S> auto-dereferences

let raw: rawptr = p to rawptr;
let back: ptr<Point> = raw to ptr<Point>;
print(back.y);            // 4
```

### Casts

```jk
let big: int = 1000;
let small: u8 = big to u8;    // explicit narrowing
let addr: u64 = &big to u64;  // pointer → integer address
```

### Extern / FFI

```jk
extern "C" puts(s: ptr<char>) -> int;
link "msvcrt";

puts("hello from C");
```

---

## 4. Inspect compilation output

```powershell
# See what LLVM IR your program produces
.\build\bin\jocky.exe build --emit-llvm examples\fib.jk

# See tokens the lexer produces
.\build\bin\jocky.exe lex --dump-tokens examples\hello.jk

# See the AST
.\build\bin\jocky.exe parse --dump-ast examples\fib.jk
```

---

## 5. Obfuscation passes

```powershell
# Compile with IR-level obfuscation
.\build\bin\jocky.exe build --obfuscate examples\fib.jk -o fib_obf.exe
.\fib_obf.exe   # same output, harder-to-read IR

# Fixed seed for reproducible builds
.\build\bin\jocky.exe build --obfuscate --obf-seed 42 examples\fib.jk -o fib_obf.exe
```

---

## 6. Forensics tool (`jocky-mem`)

`jocky-mem.exe` is a companion tool for live Windows process inspection.

```powershell
# List memory regions of a running process
.\jocky-mem.exe inventory --pid 1234

# Scan and flag suspicious regions (RWX, unbacked, image-tampered)
.\jocky-mem.exe inventory --pid 1234

# Build a baseline hash DB of a process's on-disk .text pages
.\jocky-mem.exe baseline build --pid 1234 --out baseline.bin

# Inventory with an existing baseline (enables image-tamper detection)
.\jocky-mem.exe inventory --pid 1234 --baseline baseline.bin

# Run internal selftests
.\jocky-mem.exe selftest
# SELFTEST-PE OK  SELFTEST-RELOC OK  SELFTEST-HASH OK
```

---

## 7. Tests

```powershell
cmake --build build --target check
```

The suite uses LLVM `lit` + `FileCheck`. See [docs/testing.md](docs/testing.md).

---

## 8. Building from source

See [docs/building.md](docs/building.md). Short version:

```powershell
# First time only — vendors LLVM 18 SDK under .vendor/
.\scripts\bootstrap.ps1

# Build everything
cmake --build build
```
