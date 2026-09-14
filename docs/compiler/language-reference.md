# JOCKY Language Reference

## Why a Custom Language

`.jk` is not a general-purpose language. It is designed for one narrow purpose: writing security research tools that compile to native Windows executables via LLVM. The syntax is deliberately minimal — no object system, no generics, no exceptions. Every construct maps directly to an LLVM IR primitive, which keeps the compiler simple and the output predictable.

## Program Structure

Every `.jk` file is a flat collection of function definitions. There is no module system. The compiler expects exactly one function named `start` — this is the entry point.

```jk
func start() -> nothing {
    print(`hello world`)
}
```

Functions may call each other freely. Recursion is supported.

## Types

| Type keyword | What it is | LLVM type |
|---|---|---|
| `num` | 64-bit signed integer | `i64` |
| `dec` | 64-bit float | `double` |
| `text` | String / null-terminated char pointer | `i8*` |
| `flag` | Boolean | `i1` |
| `raw` | Byte buffer / opaque pointer | `i8*` |
| `nothing` | Void (return type only) | `void` |

## Variables

Variables are declared with `var` and must have an explicit type. Initialisation is required.

```jk
var count : num := 0
var name  : text := `scanner`
var ok    : flag := yes
```

Assignment after declaration uses `<-`:

```jk
count <- count + 1
name  <- `updated`
```

## Functions

```jk
func add(a : num, b : num) -> num {
    give a + b
}
```

- Parameters are `name : type` pairs separated by commas.
- Return type follows `->`.
- `give` is the return statement. A `nothing`-returning function uses bare `give` or falls off the end.

## Control Flow

### Conditional — `check` / `otherwise`

```jk
check count gt 0 {
    print(`positive`)
} otherwise {
    print(`zero or negative`)
}
```

`otherwise` is optional.

### Loop — `loop`

```jk
loop count lt 10 {
    count <- count + 1
}
```

Equivalent to `while (count < 10)`.

- `stop` breaks out of the innermost loop.
- `skip` continues to the next iteration.

### For-style loop

```jk
var i : num := 0
loop i lt 10 {
    print_num(i)
    i <- i + 1
}
```

There is no built-in `for` keyword; use `loop` with a counter variable.

## Operators

### Arithmetic

| Operator | Meaning |
|---|---|
| `+` | addition |
| `-` | subtraction |
| `*` | multiplication |
| `/` | division |
| `mod` | modulo |

### Comparison (word form)

| Operator | Meaning |
|---|---|
| `is` | `==` |
| `isnt` | `!=` |
| `gt` | `>` |
| `lt` | `<` |
| `gte` | `>=` |
| `lte` | `<=` |

### Logical

| Operator | Meaning |
|---|---|
| `also` | `&&` |
| `or` | `\|\|` |
| `flip` | `!` (unary) |

## Literals

| Literal | Syntax | Example |
|---|---|---|
| Integer | bare digits | `42`, `1000` |
| Float | digits with `.` | `3.14`, `-0.5` |
| String | backtick-delimited | `` `hello world` `` |
| Boolean true | `yes` | `yes` |
| Boolean false | `no` | `no` |
| Null | `empty` | `empty` |

Strings use **backticks**, not quotes. Double or single quotes are not string delimiters in `.jk`.

## Comments

Line comments start with `#`:

```jk
# This is a comment
var x : num := 42  # inline comment
```

## Standard Library

All stdlib functions are externally declared — they are provided by `stdlib.py` in JIT mode and by `forensics.c` in native builds. Call them like regular functions.

### Output

| Function | Signature | Description |
|---|---|---|
| `print` | `(msg: text) -> nothing` | Print a string to stdout |
| `print_num` | `(n: num) -> nothing` | Print a `num` |
| `print_dec` | `(d: dec) -> nothing` | Print a `dec` |
| `print_hex` | `(n: num) -> nothing` | Print a `num` as hex |

### Process Information

| Function | Signature | Description |
|---|---|---|
| `proc_list` | `() -> nothing` | Print all running processes (PID + name) |
| `proc_count` | `() -> num` | Number of running processes |
| `proc_find` | `(name: text) -> num` | PID of first process matching name, or -1 |
| `proc_name` | `(pid: num) -> text` | Name of process with given PID |
| `proc_classify` | `(pid: num) -> text` | Classify process: SYSTEM / USER / SECURITY / UNKNOWN |

### Network

| Function | Signature | Description |
|---|---|---|
| `net_connections` | `() -> nothing` | Print all active TCP connections |
| `net_conn_count` | `() -> num` | Number of active TCP connections |
| `net_find_pid` | `(pid: num) -> num` | Number of connections belonging to a PID |

### File System

| Function | Signature | Description |
|---|---|---|
| `file_exists` | `(path: text) -> flag` | Check if a path exists |
| `file_read` | `(path: text) -> text` | Read file contents as string |
| `file_hash` | `(path: text) -> text` | SHA-256 hex string of a file |
| `dir_list` | `(path: text) -> nothing` | Print directory contents |

### Registry (Windows only)

| Function | Signature | Description |
|---|---|---|
| `reg_read` | `(key: text, value: text) -> text` | Read a registry value |
| `reg_exists` | `(key: text) -> flag` | Check if a registry key exists |

### System Information

| Function | Signature | Description |
|---|---|---|
| `sys_hostname` | `() -> text` | Machine hostname |
| `sys_username` | `() -> text` | Current user name |
| `sys_os` | `() -> text` | OS version string |
| `sys_arch` | `() -> text` | CPU architecture string |
| `sys_uptime` | `() -> num` | System uptime in seconds |

### BYOVD / Kernel (requires `--kernel` flag or `KernelInterface`)

| Function | Signature | Description |
|---|---|---|
| `kernel_base` | `() -> num` | Resolve ntoskrnl.exe base address |
| `kernel_read` | `(addr: num) -> num` | Read 64-bit value from kernel address |
| `kernel_write` | `(addr: num, val: num) -> nothing` | Write 64-bit value to kernel address |
| `kernel_callbacks` | `() -> nothing` | Enumerate process-notification callbacks |
| `byovd_scan` | `() -> num` | Scan drivers; return count of vulnerable matches |

### Hashing

| Function | Signature | Description |
|---|---|---|
| `sha256` | `(path: text) -> text` | SHA-256 hex string of a file |
| `sha256_str` | `(s: text) -> text` | SHA-256 hex string of a string value |

### Timing

| Function | Signature | Description |
|---|---|---|
| `sleep_ms` | `(ms: num) -> nothing` | Sleep for N milliseconds |
| `timestamp` | `() -> num` | Unix timestamp (seconds) |

## Complete Example

```jk
func is_security_process(pid : num) -> flag {
    var cls : text := proc_classify(pid)
    check cls is `SECURITY` {
        give yes
    }
    give no
}

func start() -> nothing {
    print(`=== Process Scanner ===`)
    var total : num := proc_count()
    print_num(total)
    print(` processes found`)

    var i : num := 0
    loop i lt total {
        var pid  : num  := i + 1000
        var name : text := proc_name(pid)
        check is_security_process(pid) {
            print(`[EDR] `)
            print(name)
        }
        i <- i + 1
    }
}
```
