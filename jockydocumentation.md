# JOCKY Language Documentation

**A complete reference for learning and using the JOCKY programming language.**

---

## Table of Contents

1. [Introduction](#1-introduction)
2. [Quick Start](#2-quick-start)
3. [Lexical Structure](#3-lexical-structure)
4. [Types](#4-types)
5. [Variables and Assignment](#5-variables-and-assignment)
6. [Operators](#6-operators)
7. [Control Flow](#7-control-flow)
8. [Functions](#8-functions)
9. [Expressions](#9-expressions)
10. [Standard Library](#10-standard-library)
11. [Complete Program Examples](#11-complete-program-examples)
12. [Compilation and Execution](#12-compilation-and-execution)
13. [Error Reference](#13-error-reference)

---

## 1. Introduction

JOCKY is a compiled, statically-typed programming language designed for Windows forensics and cybersecurity tooling. It was built for the Smart India Hackathon (SIH) and uses LLVM as its compilation backend, producing either JIT-executed code or standalone native `.exe` binaries via MinGW gcc.

### Design Goals

- **Custom syntax** — JOCKY source files (`.jk`) use a unique keyword vocabulary that antivirus parsers do not recognise, making source-level analysis harder.
- **XOR-encrypted string literals** — In native binary builds, all string constants are XOR-encrypted at compile time and decrypted transparently at runtime, preventing static string scanning.
- **Polymorphic builds** — Every compilation injects a random 16-byte build-ID and a random entropy constant, ensuring that two builds of the same source produce different SHA-256 hashes.
- **Native performance** — JOCKY compiles to LLVM IR, which is then lowered to native machine code, delivering full native speed with no interpreter overhead.

### Technology Stack

| Component | Role |
|-----------|------|
| Python 3.10+ | Compiler toolchain (lexer, parser, codegen) |
| llvmlite | Python bindings to the LLVM IR builder and MCJIT engine |
| MinGW gcc | Native Windows linker for `.exe` production |
| `forensics.c` | C implementation of the JOCKY standard library |

---

## 2. Quick Start

### Prerequisites

- Python 3.10 or newer
- llvmlite (`pip install llvmlite`)
- MinGW gcc (for native binary builds only)
- Optional: `rich` (`pip install rich`) for the enhanced TUI

### Your First JOCKY Program

Create a file called `hello.jk`:

```
func start() -> nothing {
    report(`Hello, JOCKY!`)
}
```

Run it immediately with the JIT engine:

```
python jocky.py run hello.jk
```

Or open the interactive TUI (no arguments):

```
python jocky.py
```

### The Entry Point

Every runnable JOCKY program **must** define a function named `start` that takes no parameters and returns `nothing`:

```
func start() -> nothing {
    ## your program here
}
```

This is analogous to `main()` in C/C++ or `public static void main` in Java.

---

## 3. Lexical Structure

### 3.1 Source Files

JOCKY source files use the `.jk` extension and must be encoded as UTF-8.

### 3.2 Comments

Only single-line comments are supported. A comment begins with `##` and extends to the end of the line:

```
## This is a comment
var x : num := 42  ## inline comment
```

There are no block or multi-line comment delimiters.

### 3.3 Whitespace

Spaces, tabs, carriage returns, and newlines are all treated as whitespace and ignored by the lexer. JOCKY is a free-form language — indentation has no semantic meaning.

### 3.4 Keywords

The following words are reserved and cannot be used as identifiers:

| Keyword | Meaning |
|---------|---------|
| `func` | Function definition |
| `var` | Variable declaration |
| `check` | Conditional (if) |
| `otherwise` | Alternative branch (else) |
| `loop` | While loop |
| `give` | Return statement |
| `stop` | Break out of a loop |
| `skip` | Continue to next iteration |
| `yes` | Boolean true |
| `no` | Boolean false |
| `empty` | Null / void value |
| `num` | 64-bit integer type |
| `dec` | 64-bit float type |
| `text` | String type |
| `flag` | Boolean type |
| `raw` | Opaque pointer type |
| `nothing` | Void return type |
| `is` | Equality comparison (`==`) |
| `isnt` | Inequality comparison (`!=`) |
| `gt` | Greater-than (`>`) |
| `lt` | Less-than (`<`) |
| `gte` | Greater-than-or-equal (`>=`) |
| `lte` | Less-than-or-equal (`<=`) |
| `also` | Logical AND (`&&`) |
| `or` | Logical OR (`\|\|`) |
| `flip` | Logical NOT (`!`) |
| `mod` | Modulo (`%`) |

### 3.5 Identifiers

An identifier begins with a letter (`a-z`, `A-Z`) or an underscore (`_`), followed by any number of letters, digits, or underscores. Identifiers are case-sensitive.

```
## Valid identifiers
my_var
_count
processName
x1

## Invalid — starts with a digit
1bad
```

### 3.6 String Literals

Strings are enclosed in **backticks** (`` ` ``), not single or double quotes. A string literal cannot span multiple lines.

```
var greeting : text := `Hello, world!`
var path      : text := `C:\Windows\System32`
```

### 3.7 Number Literals

Integer literals are sequences of digits with no underscores or separators:

```
42
1000
0
```

Floating-point literals include a decimal point followed by at least one digit:

```
3.14
0.5
100.0
```

---

## 4. Types

JOCKY has six built-in types. Every variable and parameter must declare its type explicitly.

### 4.1 `num` — 64-bit Integer

Signed 64-bit integer. Corresponds to `int64_t` in C and `i64` in LLVM IR.

```
var count : num := 0
var pid   : num := 1234
```

### 4.2 `dec` — 64-bit Float

IEEE 754 double-precision float. Corresponds to `double` in C and `f64` (double) in LLVM IR.

```
var ratio : dec := 3.14
var score : dec := 0.0
```

### 4.3 `text` — String

A null-terminated character string (`char*` in C, `i8*` in LLVM IR). Literals are backtick-delimited. Strings are immutable at the language level; the `raw` type is used for mutable byte buffers.

```
var name    : text := `svchost.exe`
var message : text := `Threat detected`
```

**String comparison** uses the `is` / `isnt` operators, which internally call `strcmp`:

```
check (name is `lsass.exe`) {
    report(`Sensitive process found`)
}
```

### 4.4 `flag` — Boolean

A boolean value. Literals are `yes` (true) and `no` (false). Corresponds to `i1` in LLVM IR.

```
var found  : flag := no
var active : flag := yes
```

### 4.5 `raw` — Opaque Pointer

An untyped `void*` pointer used to hold opaque data handles returned by stdlib functions. You cannot dereference a `raw` value directly in JOCKY — you must pass it to other stdlib functions that understand its internal layout.

```
var procs : raw := procs_list()      ## get process list handle
var count : num := proc_count(procs) ## pass handle to count function
```

### 4.6 `nothing` — Void

Used only as the declared return type of functions that do not return a value. Cannot be used as a variable type.

```
func report_result(msg : text) -> nothing {
    report(msg)
}
```

### 4.7 Type Coercion Rules

- `num` and `dec` are mutually assignable (the compiler inserts `sitofp` / `fptosi` instructions automatically).
- `raw` can be assigned `empty` (null pointer).
- All other type combinations are type errors detected at compile time.

---

## 5. Variables and Assignment

### 5.1 Declaration

Every variable must be declared with `var`, a name, a type annotation, and an initialiser. There is no uninitialised declaration.

```
var name : type := initialiser
```

Examples:

```
var count     : num  := 0
var threshold : dec  := 0.75
var label     : text := `unknown`
var active    : flag := no
var procs     : raw  := procs_list()
```

Variables are scoped to the enclosing block `{ }`. A variable declared in an inner block shadows an outer variable of the same name within that block.

### 5.2 Assignment

After declaration, a variable is reassigned using the `<-` arrow operator:

```
count <- count + 1
label <- `threat detected`
active <- yes
```

The left-hand side must be a previously declared variable name. Assigning a value of an incompatible type is a semantic error.

---

## 6. Operators

### 6.1 Arithmetic Operators

These operate on `num` and `dec` values. When one operand is `dec`, both are promoted to `dec` and the result is `dec`.

| Operator | Meaning | Example |
|----------|---------|---------|
| `+` | Addition | `x + 1` |
| `-` | Subtraction | `total - 1` |
| `*` | Multiplication | `count * 2` |
| `/` | Division (integer division for `num`) | `size / 4` |
| `mod` | Modulo (remainder) | `i mod 3` |
| `-` (unary) | Negation | `-count` |

### 6.2 Comparison Operators

These produce a `flag` result.

| Operator | Meaning | Valid Operand Types |
|----------|---------|---------------------|
| `is` | Equal to | Any matching types; `text` uses `strcmp` |
| `isnt` | Not equal to | Any matching types; `text` uses `strcmp` |
| `gt` | Greater than | `num`, `dec` |
| `lt` | Less than | `num`, `dec` |
| `gte` | Greater than or equal | `num`, `dec` |
| `lte` | Less than or equal | `num`, `dec` |

### 6.3 Logical Operators

These operate on `flag` values and produce `flag`.

| Operator | Meaning | Example |
|----------|---------|---------|
| `also` | Logical AND | `a also b` |
| `or` | Logical OR | `a or b` |
| `flip` | Logical NOT (unary) | `flip active` |

### 6.4 Assignment Operators

| Operator | Meaning | Example |
|----------|---------|---------|
| `:=` | Initialise (declaration only) | `var x : num := 0` |
| `<-` | Assign (existing variable) | `x <- x + 1` |

### 6.5 Operator Precedence (highest to lowest)

1. Unary: `flip`, unary `-`
2. Multiplicative: `*`, `/`, `mod`
3. Additive: `+`, `-`
4. Comparison: `is`, `isnt`, `gt`, `lt`, `gte`, `lte`
5. Logical: `also`, `or`

Parentheses `( )` override precedence at any level:

```
var result : flag := (a gt 0) also (b lt 10)
```

---

## 7. Control Flow

### 7.1 Conditional — `check` / `otherwise`

```
check (condition) {
    ## executed when condition is yes
}
```

With an else branch:

```
check (condition) {
    ## executed when condition is yes
} otherwise {
    ## executed when condition is no
}
```

The condition must be of type `flag`. Conditions that are numeric or string values are type errors.

Example:

```
check (score gt 40) {
    report(`High threat score — system likely compromised`)
} otherwise {
    report(`No significant threat detected`)
}
```

Nested checks:

```
check (score is 0) {
    report(`Clean`)
}
check (score gt 0) {
    check (score lt 15) {
        report(`Low risk`)
    }
    check (score gte 15) {
        report(`Moderate risk`)
    }
}
```

### 7.2 Loop — `loop`

A `loop` executes its body as long as its condition remains `yes`:

```
loop (condition) {
    ## body
}
```

Example — iterate over a process list:

```
var i : num := 0
loop (i lt total) {
    var name : text := proc_name(procs, i)
    report(name)
    i <- i + 1
}
```

The condition is re-evaluated before every iteration.

### 7.3 Break — `stop`

`stop` immediately exits the innermost `loop`:

```
var i : num := 0
loop (i lt 100) {
    check (i is 5) {
        stop
    }
    i <- i + 1
}
## i == 5 here
```

### 7.4 Continue — `skip`

`skip` jumps to the condition check of the innermost `loop`, skipping the rest of the current iteration's body:

```
var i : num := 0
loop (i lt 10) {
    i <- i + 1
    check (i mod 2 is 0) {
        skip   ## skip even numbers
    }
    report(`odd`)
}
```

### 7.5 Return — `give`

Return a value from a function:

```
give expression
```

Return without a value (void return from a `nothing` function):

```
give
```

`give` terminates the current function immediately. Any code after `give` in the same block is unreachable.

---

## 8. Functions

### 8.1 Defining a Function

```
func name(param1 : type1, param2 : type2) -> return_type {
    ## body
}
```

- Parameter names and their types are listed inside parentheses, separated by commas.
- The return type follows `->`.
- Functions with no parameters use empty parentheses: `func start() -> nothing { ... }`.
- Functions with a `nothing` return type may omit the `give` statement; an implicit void return is inserted.

### 8.2 Calling a Function

```
function_name(arg1, arg2)
```

A function call is an expression. If the return type is not `nothing`, the result can be used in an expression:

```
var count : num := proc_count(procs)
var cls   : num := classify(name)
```

If the return type is `nothing`, the call is used as a statement:

```
report(`Scan complete`)
run_captures()
```

### 8.3 Forward Calls

JOCKY performs a two-pass registration of all function signatures before analysing bodies. This means functions can call each other regardless of declaration order, with no need for forward declarations.

### 8.4 The `start` Function

The program entry point is always named `start`:

```
func start() -> nothing {
    ## top-level program logic goes here
}
```

In native binary mode, a small C shim (`int main(){ start(); return 0; }`) is compiled alongside the JOCKY object file. The linker combines them so the OS launches `main`, which immediately calls `start`.

### 8.5 Recursion

JOCKY supports recursion. The compiler declares all functions before generating bodies, so a function can call itself:

```
func factorial(n : num) -> num {
    check (n lte 1) { give 1 }
    give n * factorial(n - 1)
}
```

---

## 9. Expressions

### 9.1 Literals

| Literal | Type | Example |
|---------|------|---------|
| Integer | `num` | `42`, `0`, `9999` |
| Float | `dec` | `3.14`, `0.5` |
| String | `text` | `` `hello world` `` |
| Boolean true | `flag` | `yes` |
| Boolean false | `flag` | `no` |
| Null | (assignable to `raw`) | `empty` |

### 9.2 Identifiers

A bare name refers to the value of the variable declared in the nearest enclosing scope:

```
var x : num := 10
var y : num := x + 5   ## x refers to the variable above
```

### 9.3 Parenthesised Expressions

Wrap any expression in `( )` to control grouping:

```
var result : num := (a + b) * c
var ok     : flag := (x gt 0) also (y lt 100)
```

### 9.4 Binary Expressions

```
left operator right
```

### 9.5 Unary Expressions

```
flip boolean_expr     ## logical NOT
- numeric_expr        ## arithmetic negation
```

### 9.6 Function Calls as Expressions

When a function returns a non-`nothing` type, its call is an expression:

```
var n     : num  := proc_count(procs)
var name  : text := proc_name(procs, 0)
var found : flag := (name is `lsass.exe`)
```

---

## 10. Standard Library

JOCKY comes with a built-in standard library of forensics-oriented functions. These are declared automatically before any user code; no import statement is needed.

In **JIT mode** (`--run`), these functions are backed by Python `ctypes` callbacks in `stdlib.py`.

In **native binary mode**, they are implemented in `stdlib/forensics.c` and linked into the final executable by gcc.

---

### 10.1 Output

#### `report(msg : text) -> nothing`

Print a message to stdout with a `[JOCKY]` prefix.

```
report(`Scan started`)
report(process_name)
```

---

### 10.2 Process Enumeration

#### `procs_list() -> raw`

Return an opaque handle to the current list of running processes. Must be passed to all other `proc_*` functions.

```
var procs : raw := procs_list()
```

#### `proc_count(procs : raw) -> num`

Return the number of processes in the list.

```
var total : num := proc_count(procs)
```

#### `proc_name(procs : raw, index : num) -> text`

Return the name of the process at the given zero-based index.

```
var name : text := proc_name(procs, i)
```

#### `proc_pid(procs : raw, index : num) -> num`

Return the process ID (PID) of the process at the given index.

```
var pid : num := proc_pid(procs, i)
```

#### `proc_kill(pid : num) -> nothing`

Terminate the process with the given PID.

```
proc_kill(malicious_pid)
```

#### `proc_mem_read(pid : num, addr : num, size : num) -> raw`

Read `size` bytes from the address space of process `pid` starting at `addr`. Returns a raw byte buffer.

```
var mem : raw := proc_mem_read(pid, 0x7FF000, 256)
```

---

### 10.3 Network

#### `net_conns() -> raw`

Return a handle representing the current active TCP/UDP connections.

```
var conns : raw := net_conns()
```

#### `net_sniff(duration_ms : num) -> raw`

Perform a passive packet capture for `duration_ms` milliseconds. Returns a raw packet buffer.

```
var packets : raw := net_sniff(2000)   ## 2-second capture
```

---

### 10.4 Windows Registry

#### `reg_read(key : text, value_name : text) -> text`

Read a registry value. Returns the value as a string, or an empty string if not found.

```
var shell : text := reg_read(
    `SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`,
    `Shell`
)
check (shell isnt `explorer.exe`) {
    report(`Winlogon Shell hijacked`)
}
```

#### `reg_list(key : text) -> raw`

List the subkeys of a registry key. Returns a raw handle.

```
var keys : raw := reg_list(`SOFTWARE\Microsoft\Windows NT\CurrentVersion`)
```

---

### 10.5 File System

#### `file_list(path : text) -> raw`

List the contents of a directory. Returns a raw handle to the directory listing.

```
var listing : raw := file_list(`C:\Windows\System32`)
```

#### `file_read(path : text) -> raw`

Read the raw bytes of a file. Returns a raw byte buffer.

```
var data : raw := file_read(`C:\Windows\System32\lsass.exe`)
```

---

### 10.6 System Information

#### `sys_info() -> raw`

Return a handle to system information (OS version, hostname, architecture, etc.).

```
var info : raw := sys_info()
```

#### `hash_file(path : text) -> raw`

Compute the SHA-256 hash of the file at `path`. Returns a 32-byte raw buffer.

```
var h : raw := hash_file(`C:\Windows\System32\svchost.exe`)
```

---

## 11. Complete Program Examples

### 11.1 Hello World

```
func start() -> nothing {
    report(`Hello, world!`)
}
```

### 11.2 Variables and Arithmetic

```
func start() -> nothing {
    var a : num := 10
    var b : num := 3
    var sum : num := a + b
    var rem : num := a mod b
    report(`Sum computed`)
    report(`Remainder computed`)
}
```

### 11.3 Loop with Counter

```
func start() -> nothing {
    var i : num := 0
    loop (i lt 5) {
        report(`tick`)
        i <- i + 1
    }
    report(`done`)
}
```

### 11.4 Conditional Logic

```
func grade(score : num) -> text {
    check (score gte 90) { give `A` }
    check (score gte 80) { give `B` }
    check (score gte 70) { give `C` }
    give `F`
}

func start() -> nothing {
    var g : text := grade(85)
    report(g)
}
```

### 11.5 Process Scanner

```
func classify(name : text) -> num {
    check (name is `mimikatz.exe`) { give 3 }
    check (name is `nc.exe`)       { give 2 }
    check (name is `lsass.exe`)    { give 1 }
    give 0
}

func start() -> nothing {
    var procs : raw := procs_list()
    var total : num := proc_count(procs)
    var i     : num := 0

    loop (i lt total) {
        var name : text := proc_name(procs, i)
        var cls  : num  := classify(name)

        check (cls is 3) { report(`[CRITICAL] `) report(name) }
        check (cls is 2) { report(`[HIGH]     `) report(name) }
        check (cls is 1) { report(`[SENSITIVE]`) report(name) }

        i <- i + 1
    }
}
```

### 11.6 Registry Integrity Check

```
func check_winlogon() -> num {
    var shell : text := reg_read(
        `SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`,
        `Shell`
    )
    check (shell isnt ``) {
        check (shell isnt `explorer.exe`) {
            report(`[CRITICAL] Winlogon Shell hijacked`)
            give 30
        }
        report(`[INFO] Custom Winlogon Shell present`)
        give 5
    }
    report(`[OK] Winlogon Shell is standard`)
    give 0
}

func start() -> nothing {
    var score : num := check_winlogon()
    check (score gt 0) {
        report(`Registry anomaly detected`)
    }
}
```

### 11.7 Boolean Logic

```
func is_suspicious(name : text, pid : num) -> flag {
    var bad_name : flag := (name is `nc.exe`) or (name is `psexec.exe`)
    var low_pid  : flag := pid lt 1000
    give bad_name also (flip low_pid)
}

func start() -> nothing {
    var procs : raw := procs_list()
    var i     : num := 0
    var total : num := proc_count(procs)

    loop (i lt total) {
        var n : text := proc_name(procs, i)
        var p : num  := proc_pid(procs, i)
        check (is_suspicious(n, p)) {
            report(`Suspicious process:`)
            report(n)
        }
        i <- i + 1
    }
}
```

---

## 12. Compilation and Execution

### 12.1 JIT Execution (`run`)

The fastest way to test a script. The JOCKY source is compiled in memory to LLVM IR, which is then JIT-compiled via LLVM's MCJIT engine and executed immediately. The stdlib functions are provided as Python `ctypes` callbacks.

```
python jocky.py run scripts/proc_scanner.jk
```

With structural obfuscation (build-ID and entropy injection; string XOR is not available in JIT mode):

```
python jocky.py run scripts/proc_scanner.jk --obfuscate
```

### 12.2 Native Binary (`build`)

Produces a standalone `.exe` with no Python dependency. The pipeline is:

1. Compile `.jk` → LLVM IR
2. Apply obfuscation passes (XOR string encryption, polymorphic build-ID, entropy)
3. Lower IR to object code via the LLVM target machine
4. Compile a small C entry shim (`int main(){ start(); return 0; }`)
5. Link: `jocky.o` + `forensics.o` + `entry_shim.o` → `.exe` via MinGW gcc

```
python jocky.py build scripts/proc_scanner.jk
```

Debug build (no obfuscation):

```
python jocky.py build scripts/proc_scanner.jk --no-obfuscate
```

### 12.3 Inspection Commands

| Command | What it does |
|---------|-------------|
| `python jocky.py show file.jk` | Print source with line numbers |
| `python jocky.py tokens file.jk` | Print the token list from the lexer |
| `python jocky.py ast file.jk` | Print the Abstract Syntax Tree |
| `python jocky.py ir file.jk` | Print clean LLVM IR |
| `python jocky.py ir-obf file.jk` | Print obfuscated LLVM IR |
| `python jocky.py inspect file.jk` | Full pipeline summary (all 5 stages) |

### 12.4 The Interactive TUI

Running `python jocky.py` (or `jocky.bat` on Windows) opens a menu-driven terminal UI with:

- Pre-built cybersecurity scripts (Process Scanner, Network Monitor, Threat Hunter, etc.)
- Custom script editor with workspace management
- In-line pipeline inspector (tokens, AST, IR)
- Native binary builder
- Language reference card
- About page

---

## 13. Error Reference

### Lexer Errors

| Error | Cause |
|-------|-------|
| `unexpected character 'X'` | A character not in the JOCKY alphabet was found |
| `unterminated string literal (no closing backtick)` | A string started with `` ` `` but no closing `` ` `` was found before a newline |
| `unterminated string literal (reached end of file)` | A string started with `` ` `` but the file ended before it was closed |

### Parse Errors

| Error | Cause |
|-------|-------|
| `Expected 'func', got ...` | Top-level code outside a function definition |
| `Expected IDENTIFIER, got ...` | Missing name in a function or variable declaration |
| `Expected a type keyword, got ...` | Unrecognised type annotation |
| `Expected ':=', got ...` | Missing initialiser in variable declaration |
| `Expected '->', got ...` | Missing return-type arrow in function signature |
| `Unexpected token ... in expression` | An invalid token appeared where an expression was expected |

### Semantic Errors

| Error | Cause |
|-------|-------|
| `Undefined variable 'x'` | Using a variable before declaring it |
| `Undefined function 'f'` | Calling a function that was never defined |
| `Type mismatch in variable 'x': expected 'num', got 'text'` | Assigning a value of the wrong type |
| `'check' condition must be 'flag'` | Using a non-boolean condition |
| `'loop' condition must be 'flag'` | Using a non-boolean loop condition |
| `Operator '+' requires numeric types` | Arithmetic on non-numeric types |
| `Function 'f' expects 2 argument(s), got 1` | Wrong number of arguments in a call |
| `'flip' requires 'flag' operand` | Applying logical NOT to a non-boolean |
