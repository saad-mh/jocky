# JOCKY Application — System Architecture

**A complete technical reference explaining every component of the JOCKY Application and how they interact.**

---

## Table of Contents

1. [High-Level Overview](#1-high-level-overview)
2. [Directory Layout](#2-directory-layout)
3. [Compilation Pipeline](#3-compilation-pipeline)
   - [Stage 1: Lexer](#31-stage-1-lexer)
   - [Stage 2: Parser](#32-stage-2-parser)
   - [Stage 3: Semantic Analyser](#33-stage-3-semantic-analyser)
   - [Stage 4: Code Generator](#34-stage-4-code-generator)
   - [Stage 5: Obfuscation Passes](#35-stage-5-obfuscation-passes)
4. [Execution Paths](#4-execution-paths)
   - [JIT Execution Path](#41-jit-execution-path)
   - [Native Binary Path](#42-native-binary-path)
5. [Standard Library Architecture](#5-standard-library-architecture)
6. [CLI and TUI Layer](#6-cli-and-tui-layer)
7. [Data Flow](#7-data-flow)
8. [Symbol Table](#8-symbol-table)
9. [Type System Internals](#9-type-system-internals)
10. [Obfuscation Architecture](#10-obfuscation-architecture)
11. [Module Dependencies](#11-module-dependencies)

---

## 1. High-Level Overview

The JOCKY Application is a self-contained cybersecurity language toolchain. Its primary inputs are `.jk` source files; its outputs are either immediate program execution via LLVM JIT or standalone Windows `.exe` binaries.

```
┌──────────────────────────────────────────────────────────────────────┐
│                          JOCKY Application                           │
│                                                                      │
│   ┌─────────────┐    ┌──────────────────────────────────────────┐   │
│   │  jocky.py   │    │  jocky_terminal.py  (Interactive TUI)   │   │
│   │  (CLI)      │    │  Rich-based menu  ·  Script runner       │   │
│   └──────┬──────┘    └────────────────────┬─────────────────────┘   │
│          │                                │                          │
│          └────────────────┬───────────────┘                          │
│                           ▼                                          │
│              ┌────────────────────────┐                              │
│              │  compiler/compiler.py  │                              │
│              │  (Pipeline Orchestrator)│                              │
│              └────────────┬───────────┘                              │
│                           │                                          │
│        ┌──────────────────▼──────────────────────┐                  │
│        │            Compiler Pipeline             │                  │
│        │                                          │                  │
│        │  lexer.py  →  parser.py  →  semantic.py  │                  │
│        │       →  codegen.py  →  passes.py         │                  │
│        └──────────────────┬──────────────────────┘                  │
│                           │                                          │
│              ┌────────────┴────────────┐                             │
│              │                         │                             │
│        ┌─────▼──────┐          ┌───────▼──────┐                     │
│        │  JIT Mode  │          │ Native Mode  │                     │
│        │  LLVM MCJIT │          │  gcc linker  │                     │
│        │  + stdlib.py│          │  + forensics.o│                    │
│        └────────────┘          └──────────────┘                     │
└──────────────────────────────────────────────────────────────────────┘
```

---

## 2. Directory Layout

```
JOCKY Application/
│
├── jocky.py                # CLI entry point — subcommand dispatcher
├── jocky_terminal.py       # Interactive TUI (Rich-based menu system)
├── jocky.bat               # Windows launcher wrapper
├── jocky.sh                # Linux/Mac launcher wrapper
├── requirements.txt        # Python dependencies (llvmlite, rich)
├── setup.bat / setup.sh    # Environment setup scripts
│
├── compiler/               # Compiler toolchain
│   ├── compiler.py         # Pipeline orchestrator — main compile function
│   ├── jocky/              # Compiler package
│   │   ├── __init__.py
│   │   ├── tokens.py       # Token type definitions (TokenType enum + Token class)
│   │   ├── lexer.py        # Stage 1: Lexical analyser
│   │   ├── ast_nodes.py    # AST node dataclasses
│   │   ├── parser.py       # Stage 2: Recursive descent parser
│   │   ├── symbol_table.py # Symbol table (scope chain)
│   │   ├── semantic.py     # Stage 3: Semantic / type analyser
│   │   ├── codegen.py      # Stage 4: LLVM IR generator (llvmlite)
│   │   ├── passes.py       # Stage 5: Obfuscation passes
│   │   └── stdlib.py       # JIT stdlib — Python ctypes callbacks
│   └── stdlib/
│       ├── forensics.h     # C header — public stdlib API
│       ├── forensics.c     # C implementation — native stdlib
│       └── forensics.o     # Compiled object file (built by build_stdlib.py)
│
├── scripts/                # Pre-built forensics scripts (9 built-in)
│   ├── proc_scanner.jk
│   ├── net_monitor.jk
│   ├── net_logger.jk
│   ├── packet_sniffer.jk
│   ├── resource_monitor.jk
│   ├── sys_info.jk
│   ├── file_hasher.jk
│   ├── registry_inspector.jk
│   └── threat_hunter.jk
│
├── workspace/              # User-created scripts (editable)
│   └── example.jk
│
└── output/                 # Compiled artefacts (.ll, .o, .exe)
    └── .gitkeep
```

---

## 3. Compilation Pipeline

The pipeline is a classic 5-stage compiler design. Each stage transforms the program representation one step closer to machine code.

```
 .jk source text
       │
       ▼
┌─────────────┐
│  Stage 1    │  lexer.py
│   Lexer     │  Characters → Token stream
└──────┬──────┘
       │  list[Token]
       ▼
┌─────────────┐
│  Stage 2    │  parser.py
│   Parser    │  Tokens → AST
└──────┬──────┘
       │  Program (root AST node)
       ▼
┌─────────────┐
│  Stage 3    │  semantic.py
│  Semantic   │  Type-check AST + annotate inferred_type fields
│  Analyser   │
└──────┬──────┘
       │  Annotated AST
       ▼
┌─────────────┐
│  Stage 4    │  codegen.py
│   Code      │  AST → llvmlite ir.Module (LLVM IR)
│  Generator  │
└──────┬──────┘
       │  ir.Module
       ▼
┌─────────────┐
│  Stage 5    │  passes.py
│ Obfuscation │  XOR encrypt strings + inject build-ID + entropy
└──────┬──────┘
       │  Obfuscated ir.Module
       ▼
  ┌────┴─────┐
  │          │
  ▼          ▼
JIT        Native
MCJIT      .o + gcc → .exe
```

---

### 3.1 Stage 1: Lexer

**File:** `compiler/jocky/lexer.py`  
**Input:** Raw source string  
**Output:** `list[Token]`

The `Lexer` class walks the source text character by character, maintaining a position pointer, a line counter, and a column counter.

#### Scanning Rules (in priority order)

| Input | Action |
|-------|--------|
| Space, tab, `\r` | Skip (no token emitted) |
| `\n` | Skip; increment line counter |
| `##` | Skip to end of line (comment) |
| `:=` | Emit `ASSIGN` |
| `<-` | Emit `ARROW_L` |
| `->` | Emit `ARROW_R` |
| `+`, `-`, `*`, `/`, `(`, `)`, `{`, `}`, `:`, `,` | Emit single-character token |
| `` ` `` | Scan until matching `` ` ``; emit `STRING` |
| Digit | Scan digits (and one optional `.`); emit `NUMBER` or `FLOAT` |
| Letter or `_` | Scan word; look up in `KEYWORDS`; emit keyword token or `IDENTIFIER` |
| Anything else | Emit `ERROR` token with message |

The token list always ends with an `EOF` sentinel token.

#### Token Types

All token types are defined in `tokens.py` as members of the `TokenType` enum. The `KEYWORDS` dict maps raw strings (e.g. `"func"`) to their enum values (e.g. `TokenType.FUNC`).

Each `Token` object carries:
- `type` — the `TokenType` enum value
- `value` — the raw string text of the token
- `line` — 1-indexed source line
- `column` — 1-indexed source column

---

### 3.2 Stage 2: Parser

**File:** `compiler/jocky/parser.py`  
**Input:** `list[Token]`  
**Output:** `Program` (root AST node)

The `Parser` uses the recursive descent technique. Each grammar production rule has its own method. Methods call each other recursively to handle nested constructs.

#### Grammar Productions

```
program          → function_def*

function_def     → 'func' IDENTIFIER '(' param_list? ')' '->' type block

param_list       → param (',' param)*
param            → IDENTIFIER ':' type

type             → 'num' | 'dec' | 'text' | 'flag' | 'raw' | 'nothing'

block            → '{' statement* '}'

statement        → var_decl
                 | assignment
                 | if_statement
                 | loop_statement
                 | return_statement
                 | 'stop'
                 | 'skip'
                 | expression_statement

var_decl         → 'var' IDENTIFIER ':' type ':=' expression
assignment       → IDENTIFIER '<-' expression
if_statement     → 'check' '(' expression ')' block ('otherwise' block)?
loop_statement   → 'loop' '(' expression ')' block
return_statement → 'give' expression?

expression       → logic
logic            → comparison (('also' | 'or') comparison)*
comparison       → arithmetic (comparison_op arithmetic)?
arithmetic       → term (('+' | '-') term)*
term             → unary (('*' | '/' | 'mod') unary)*
unary            → 'flip' unary | '-' unary | primary
primary          → NUMBER | FLOAT | STRING | 'yes' | 'no' | 'empty'
                 | IDENTIFIER '(' arg_list? ')'   (function call)
                 | IDENTIFIER                      (variable reference)
                 | '(' expression ')'
```

#### Operator Precedence (enforced by call depth)

The parser encodes precedence through the call hierarchy. Lower-precedence rules call higher-precedence rules as their operand parsers:

```
_parse_logic        (lowest)
  _parse_comparison
    _parse_arithmetic
      _parse_term
        _parse_unary
          _parse_primary   (highest)
```

#### AST Node Dataclasses

All AST nodes are defined in `ast_nodes.py` as `@dataclass` classes:

| Node | Represents |
|------|-----------|
| `Program` | Root — list of `FunctionDef` nodes |
| `FunctionDef` | `func name(params) -> type { body }` |
| `Param` | One parameter: `name : type` |
| `Block` | `{ statement* }` |
| `VarDecl` | `var name : type := init` |
| `Assignment` | `name <- value` |
| `IfStatement` | `check (cond) { then } otherwise { else }` |
| `LoopStatement` | `loop (cond) { body }` |
| `ReturnStatement` | `give [value]` |
| `BreakStatement` | `stop` |
| `SkipStatement` | `skip` |
| `ExpressionStatement` | Expression used as statement |
| `BinaryExpression` | `left op right` |
| `UnaryExpression` | `op operand` |
| `FunctionCall` | `name(args)` |
| `Identifier` | Variable reference |
| `NumberLiteral` | Integer constant |
| `FloatLiteral` | Float constant |
| `StringLiteral` | String constant |
| `BoolLiteral` | `yes` / `no` |
| `EmptyLiteral` | `empty` (null) |

Every expression node has an `inferred_type` field initialised to `None` and filled in by the semantic analyser.

---

### 3.3 Stage 3: Semantic Analyser

**File:** `compiler/jocky/semantic.py`  
**Input:** `Program` AST (unannotated)  
**Output:** Same `Program` AST with `inferred_type` fields populated; raises `SemanticError` if violations found.

#### Two-Pass Design

**Pass 1 — Signature registration:** All user function signatures are registered in the symbol table before any body is analysed. This allows functions to call each other regardless of declaration order.

**Pass 2 — Body analysis:** Each function body is walked recursively. Every expression node is visited to:
1. Verify all referenced names exist in scope.
2. Check type compatibility.
3. Annotate the node's `inferred_type` field.

#### Stdlib Pre-seeding

Before either pass runs, the `STDLIB_SIGNATURES` dictionary is used to pre-populate function signatures for all 15 stdlib functions (`report`, `procs_list`, `proc_count`, etc.). User code can then call these functions without declaring them.

#### Type Checking Rules

| Rule | Detail |
|------|--------|
| Arithmetic operators | Both operands must be `num` or `dec`; result is `dec` if either is `dec` |
| Comparison `is`/`isnt` | Same type required; numeric types are cross-comparable |
| Ordering `gt`/`lt`/`gte`/`lte` | Both operands must be numeric |
| Logical `also`/`or` | Both operands must be `flag` |
| `flip` | Operand must be `flag` |
| `check` condition | Must be `flag` |
| `loop` condition | Must be `flag` |
| Variable initialisation | Initialiser type must match declared type (numeric types are cross-assignable) |
| Return value | Must match the function's declared return type |
| `num` ↔ `dec` | Mutually assignable; compiler auto-inserts conversion instructions |
| `raw` ← `empty` | Legal (null pointer assignment) |

---

### 3.4 Stage 4: Code Generator

**File:** `compiler/jocky/codegen.py`  
**Input:** Annotated `Program` AST  
**Output:** `llvmlite.ir.Module` (LLVM IR)

The `CodeGenerator` class uses the `llvmlite` Python library to build an LLVM IR module directly in memory, without writing any textual IR files.

#### LLVM Type Mapping

| JOCKY type | LLVM type |
|------------|-----------|
| `num` | `i64` (64-bit signed integer) |
| `dec` | `double` (64-bit IEEE 754) |
| `text` | `i8*` (pointer to bytes) |
| `flag` | `i1` (1-bit integer) |
| `raw` | `i8*` (opaque pointer) |
| `nothing` | `void` |

#### Code Generation Strategy

**Variables:** Every local variable is allocated on the stack with `alloca`. Reads use `load`; writes use `store`. This SSA-compatible approach lets LLVM's optimiser promote allocas to registers where possible.

**Parameters:** On function entry, each parameter is stored into its own `alloca` slot and added to the `value_table` (a dict from name → `AllocaInstr`). This allows parameters to be reassigned like any other variable.

**Functions:** Generated in two passes:
1. Declare all user functions (emit `ir.Function` objects) so forward calls resolve.
2. Generate function bodies.

**Control flow:** Each `check` (if) and `loop` (while) creates multiple LLVM basic blocks:

For `check (cond) { then } otherwise { else }`:
```
current_block:
    cbranch cond → then_bb | else_bb

then_bb:
    <then body>
    branch → merge_bb

else_bb:
    <else body or empty>
    branch → merge_bb

merge_bb:
    <continues>
```

For `loop (cond) { body }`:
```
current_block:
    branch → cond_bb

cond_bb:
    <evaluate cond>
    cbranch cond → body_bb | exit_bb

body_bb:
    <body>
    branch → cond_bb   (back-edge)

exit_bb:
    <continues>
```

**Break (`stop`) and Continue (`skip`):** Implemented using a stack of basic block targets. `break_stack` tracks `exit_bb` for each active loop; `continue_stack` tracks `cond_bb`. `stop` emits `branch break_stack[-1]`; `skip` emits `branch continue_stack[-1]`.

**String literals:** Each string constant becomes a global byte array (`[N x i8]`) with `internal` linkage. At the call site, a `gep` gets a pointer to its first byte, then `jk_xordecrypt` is called. When obfuscation is disabled the XOR key is 0, so `jk_xordecrypt` is a no-op identity copy.

**String comparison (`is`/`isnt` on text):** When both operands are pointer types, the generated code calls the C `strcmp` function instead of LLVM's integer comparison.

**Type coercion:** The `_coerce` helper handles:
- `int → float`: `sitofp`
- `float → int`: `fptosi`
- Integer widening: `zext`
- Integer narrowing: `trunc`

#### Stdlib Declarations

The code generator pre-declares all stdlib functions as LLVM `declare` statements so the call instructions can reference them. The actual implementations are linked in later (by MCJIT or gcc).

---

### 3.5 Stage 5: Obfuscation Passes

**File:** `compiler/jocky/passes.py`  
**Input:** `llvmlite.ir.Module`  
**Output:** Modified `llvmlite.ir.Module`

Three passes run in sequence:

#### Pass 1: Polymorphic Build-ID Injection

A 16-byte global constant (`_jocky_build_id`) is filled with cryptographically random bytes every time the compiler runs. Because this value changes on every compilation, two builds of the same source produce binaries with different SHA-256 hashes. This defeats hash-based antivirus signature matching.

```c
// In the IR:
@_jocky_build_id = internal constant [16 x i8] c"\xA3\x7F...\x2B"
```

#### Pass 2: String XOR Encryption

A single random byte key (1–255) is chosen per compilation. Every `.jk_str.*` global (the string constant arrays emitted by the code generator) is XOR-encrypted with this key. The key is written into the `_jocky_xor_key` global, which `jk_xordecrypt` in `forensics.c` reads at runtime to transparently decrypt strings before use.

Effect: The `.exe` binary contains no readable string literals. Static string scanners (e.g. the `strings` utility) cannot extract plaintext program output.

```
Key: 0x5E  (chosen at compile time, random each build)

Original:   H    e    l    l    o
            0x48 0x65 0x6C 0x6C 0x6F

Encrypted:  0x16 0x3B 0x32 0x32 0x31   (each byte XORed with 0x5E)

Runtime:    jk_xordecrypt reads key 0x5E, XORs back → "Hello"
```

#### Pass 3: Instruction Substitution (Entropy Injection)

A random 64-bit value is written into a global constant `_jocky_entropy`. This further differentiates the binary data section between builds, complementing the build-ID polymorphism.

#### Obfuscation in JIT Mode

String XOR requires `forensics.c`'s `jk_xordecrypt` implementation, which is only available when the native library is linked. In JIT mode, the Python `jk_xordecrypt` callback simply copies the string (identity operation, key = 0). Therefore:
- JIT mode: only Pass 1 (build-ID) and Pass 3 (entropy) are applied.
- Native mode: all three passes run, including full string XOR.

---

## 4. Execution Paths

### 4.1 JIT Execution Path

```
compile_jocky(..., run_jit=True)
         │
         ├── Stages 1–4: produce ir.Module
         │
         ├── [Optional] Structural obfuscation (build-ID + entropy only)
         │
         ├── llvm.parse_assembly(ir_text)   ← parse IR text into llvmlite binding
         ├── llvm_mod.verify()              ← LLVM IR verifier
         │
         ├── stdlib.register_all()          ← register Python ctypes callbacks
         │                                    with LLVM's global symbol table
         │
         ├── llvm.create_mcjit_compiler(llvm_mod, tm)
         ├── engine.finalize_object()        ← JIT compile to native code
         ├── engine.get_function_address('start')
         └── ctypes.CFUNCTYPE(None)(func_addr)()  ← call 'start'
```

The Python `stdlib.py` callbacks are registered via `llvm.add_symbol(name, address)`. When the JIT engine encounters a `call report(...)` instruction, it resolves the symbol to the Python function's address and calls it through the C ABI.

### 4.2 Native Binary Path

```
compile_jocky(..., run_jit=False)
         │
         ├── Stages 1–5: produce obfuscated ir.Module
         │
         ├── llvm.parse_assembly(ir_text)
         ├── llvm_mod.verify()
         │
         ├── tm = target.create_target_machine(opt=2, reloc='static')
         ├── obj_bytes = tm.emit_object(llvm_mod)  ← compile to .o
         ├── write .o file
         ├── compute SHA-256 of .o (polymorphism proof)
         │
         ├── compile entry shim:
         │     gcc -c _jocky_entry.c -o _jocky_entry.o
         │     (contains: int main(){ start(); return 0; }
         │      + __chkstk trampoline for MinGW compatibility)
         │
         └── link:
               gcc jocky.o forensics.o _jocky_entry.o -o output.exe -mconsole
```

The `reloc='static'` flag prevents position-independent code (PIC) GOT references that MinGW's PE/COFF linker cannot handle. The `__chkstk` trampoline bridges the LLVM-emitted `__chkstk` symbol (MSVC ABI) to MinGW's `___chkstk_ms` (same semantics, different name).

---

## 5. Standard Library Architecture

The stdlib has two implementations, selected by execution mode:

### 5.1 JIT Implementation (`stdlib.py`)

Python `ctypes` callback functions registered via `llvm.add_symbol`. Each function is wrapped in a `ctypes.CFUNCTYPE` decorator specifying its C signature. Callback objects are stored in `_CALLBACKS` to prevent garbage collection during JIT execution.

```
Function name     Python signature                         Behaviour
─────────────────────────────────────────────────────────────────────
report            (c_char_p) → None                        print
procs_list        () → c_void_p                            return 1 (sentinel)
proc_count        (c_void_p) → c_int64                     return 7 (static list)
proc_name         (c_void_p, c_int64) → c_void_p           index into _PROCESS_TABLE
proc_pid          (c_void_p, c_int64) → c_int64            index into _PROCESS_TABLE
proc_kill         (c_int64) → None                         print
proc_mem_read     (c_int64, c_int64, c_int64) → c_void_p  print + return zeroed buffer
net_conns         () → c_void_p                            print + return stub buffer
net_sniff         (c_int64) → c_void_p                     print + return stub buffer
reg_read          (c_char_p, c_char_p) → c_void_p          print + return empty string
reg_list          (c_char_p) → c_void_p                    print + return stub buffer
file_list         (c_char_p) → c_void_p                    print + return stub buffer
file_read         (c_char_p) → c_void_p                    print + return stub buffer
sys_info          () → c_void_p                            print + return stub buffer
hash_file         (c_char_p) → c_void_p                    print + return zeroed buffer
jk_xordecrypt     (c_char_p, c_int64) → c_void_p           identity copy (key=0)
```

The static process table used in JIT mode:
```python
_PROCESS_TABLE = [
    ('svchost.exe',  1234),
    ('explorer.exe', 5678),
    ('lsass.exe',    9012),
    ('winlogon.exe', 3456),
    ('csrss.exe',    7890),
    ('cmd.exe',      2222),
    ('python.exe',   3333),
]
```

### 5.2 Native Implementation (`forensics.c`)

A C source file compiled to `forensics.o` by `build_stdlib.py` (which runs `gcc -c stdlib/forensics.c -o stdlib/forensics.o -O2`).

The C implementation exposes the same function signatures as the JIT callbacks. The process list is a statically initialised `ProcessList` struct (`g_procs`). Network, registry, and file functions are stub implementations that print to stdout and return allocated buffers. In a production deployment, these stubs would be replaced with real Windows API calls (`EnumProcesses`, `RegQueryValueExW`, `WinSock2`, etc.).

The `jk_xordecrypt` function reads the `_jocky_xor_key` byte global (exported from the compiled JOCKY object file) and XOR-decrypts the given buffer:

```c
extern unsigned char _jocky_xor_key;

char* jk_xordecrypt(const char* enc, int64_t n) {
    char* buf = malloc(n + 1);
    unsigned char key = _jocky_xor_key;
    for (int64_t i = 0; i < n; i++)
        buf[i] = enc[i] ^ key;
    buf[n] = '\0';
    return buf;
}
```

---

## 6. CLI and TUI Layer

### 6.1 CLI Entry Point (`jocky.py`)

The CLI is a subcommand dispatcher. It accepts a command as `sys.argv[1]` and delegates to one of the following command functions:

| Command | Function | What it does |
|---------|----------|-------------|
| `run <file>` | `cmd_run` | JIT-execute via subprocess |
| `build <file>` | `cmd_build` | Native binary via subprocess |
| `show <file>` | `cmd_show` | Print source with line numbers |
| `tokens <file>` | `cmd_tokens` | Lex and print token table |
| `ast <file>` | `cmd_ast` | Parse and print AST tree |
| `ir <file>` | `cmd_ir(obfuscate=False)` | Print clean LLVM IR |
| `ir-obf <file>` | `cmd_ir(obfuscate=True)` | Print obfuscated LLVM IR |
| `inspect <file>` | `cmd_inspect` | Full 5-stage pipeline summary |
| (no args) | Launches TUI | Imports and calls `jocky_terminal.main_menu()` |

The `run` and `build` commands invoke the compiler as a **subprocess** (`subprocess.run`) rather than importing it directly. This isolates the compilation environment and ensures UTF-8 I/O on Windows (`PYTHONUTF8=1`).

The `tokens`, `ast`, `ir`, and `inspect` commands import the compiler modules directly and drive the pipeline in-process, printing results to the terminal.

### 6.2 Path Resolution

The `_resolve(file_arg)` function handles three cases:
1. Absolute path → used directly.
2. Relative path that exists from the current working directory → resolved.
3. Relative path resolved against the application root directory (`APP_DIR`) → fallback.

### 6.3 Interactive TUI (`jocky_terminal.py`)

The TUI is a full-screen menu-driven application built with the `rich` library (with a plain-text fallback when `rich` is not installed).

#### Menu Structure

```
Main Menu
├── 1. Pre-built Cybersecurity Scripts
│       └── (select script) → Script Action Menu
│               ├── 1. Run (JIT, clean)
│               ├── 2. Run (JIT + Obfuscation)
│               ├── 3. View Source Code
│               ├── 4. Inspect → Tokens
│               ├── 5. Inspect → AST
│               ├── 6. Inspect → LLVM IR (clean)
│               ├── 7. Inspect → LLVM IR (obfuscated)
│               └── 8. Pipeline Summary
│
├── 2. Write / Edit Custom Script
│       ├── List workspace/*.jk files
│       ├── N → New Script (template + open editor)
│       └── (select script) → Script Action Menu (+ Edit option)
│
├── 3. Inspect Script (Tokens · AST · IR)
│       └── (select script) → Full Inspect Menu
│
├── 4. Build Native Binary (.exe)
│       └── (select script) → Build Mode Menu
│               ├── 1. Obfuscated (recommended)
│               └── 2. Debug (no obfuscation)
│
├── 5. Language Reference
│       └── (static text display)
│
├── 6. About JOCKY
│       └── (static text display)
│
└── 0. Exit
```

#### Built-in Scripts Catalogue

The TUI maintains a `BUILTIN_SCRIPTS` list defining the 9 pre-built forensics scripts with their metadata (file name, display name, description, category, tags). This list drives both the pre-built scripts menu and the inspector menu.

#### Script Execution in TUI

The TUI always executes scripts via `subprocess.run` against `compiler/compiler.py --run`. Output is captured (stdout + stderr combined) and displayed in a Rich `Panel` widget, coloured green on success and red on failure.

---

## 7. Data Flow

### 7.1 Source to JIT Execution

```
.jk file (UTF-8 text)
    │
    ▼ Lexer.tokenize()
list[Token]
    │
    ▼ Parser.parse()
Program
  └── FunctionDef[]
       └── Block
            └── Statement[]
                 └── Expression[]
    │
    ▼ SemanticAnalyzer.analyze()
Annotated Program (inferred_type filled in)
    │
    ▼ CodeGenerator.generate()
ir.Module
  ├── Global string arrays (.jk_str.0, .jk_str.1, ...)
  ├── Global: _jocky_xor_key (i8, init 0)
  ├── Extern declarations: report, procs_list, proc_count, ...
  └── User function definitions
           └── Basic blocks of LLVM instructions
    │
    ▼ [Optional] ObfuscationPasses.run_all()
Modified ir.Module
  ├── _jocky_build_id (random 16 bytes)
  ├── _jocky_entropy  (random i64)
  └── .jk_str.* globals XOR-encrypted
    │
    ▼ str(ir.Module) → IR text
    │
    ▼ llvm.parse_assembly(ir_text)
llvmlite binding Module
    │
    ▼ stdlib.register_all()  ← Python callbacks → LLVM symbol table
    │
    ▼ create_mcjit_compiler → engine.finalize_object()
Native machine code (in memory)
    │
    ▼ engine.get_function_address('start')
Function pointer → ctypes.CFUNCTYPE(None)(addr)()
    │
    ▼ Program runs; calls to report/procs_list/etc. dispatch to Python callbacks
```

### 7.2 Source to Native Binary

```
(Same as above through Stage 5)
    │
    ▼ llvm.parse_assembly → verify
    │
    ▼ tm = create_target_machine(opt=2, reloc='static')
    │
    ▼ obj_bytes = tm.emit_object(llvm_mod)
jocky.o  (COFF object file)
    │
    ├── forensics.o  (pre-built from forensics.c)
    │
    ├── _jocky_entry.o  (compiled from entry shim C code)
    │
    ▼ gcc jocky.o forensics.o _jocky_entry.o -o output.exe -mconsole
output.exe  (standalone Windows PE executable)
```

---

## 8. Symbol Table

**File:** `compiler/jocky/symbol_table.py`

The `SymbolTable` manages name resolution using a stack of scope frames. Each scope is a dict mapping names to `Symbol` objects.

```
Global scope
  ├── report: FunctionSymbol([text] → nothing)
  ├── procs_list: FunctionSymbol([] → raw)
  ├── ... (all stdlib functions)
  │
  └── start: FunctionSymbol([] → nothing)  ← user function

Function scope (for each function body)
  ├── param names
  │
  └── Block scope (per { })
       ├── var x : num
       └── Block scope (nested)
            └── var y : text
```

### Symbol Types

| Symbol Kind | Fields |
|------------|--------|
| Variable | `name`, `type_str`, `line`, `kind` (`'variable'` or `'parameter'`) |
| Function | `name`, `param_types` (list of type strings), `return_type`, `line` |

### Scope Rules

- `enter_scope()` pushes a new frame; `exit_scope()` pops it.
- `declare_var` registers a variable in the current (innermost) frame. Re-declaration in the same scope is an error.
- `lookup_var` walks frames from innermost to outermost; raises `SymbolError` if not found.
- `declare_function` and `lookup_function` operate on a separate function namespace (functions are global in scope, registered before body analysis).

---

## 9. Type System Internals

JOCKY's type system is **nominal** (types are matched by name, not structure) and **static** (all types are resolved at compile time).

### Type Representation

Internally, types are represented as plain Python strings: `'num'`, `'dec'`, `'text'`, `'flag'`, `'raw'`, `'nothing'`, and the special pseudo-type `'unknown'` used when a type error has already been reported (to suppress cascading errors).

### LLVM Type Binding

The `_jocky_to_llvm` method in `CodeGenerator` maps these strings to `llvmlite.ir` types:

```python
'num'     → ir.IntType(64)       # i64
'dec'     → ir.DoubleType()      # double
'text'    → ir.IntType(8).as_pointer()  # i8*
'flag'    → ir.IntType(1)        # i1
'raw'     → ir.IntType(8).as_pointer()  # i8*
'nothing' → ir.VoidType()        # void
```

Note that `text` and `raw` share the same LLVM type (`i8*`). The distinction exists only at the JOCKY semantic level.

### Numeric Promotion Rules

When a binary arithmetic or comparison operation has one `num` operand and one `dec` operand:
1. The semantic analyser returns type `dec` for the operation.
2. The code generator calls `_to_float` on the integer operand, inserting a `sitofp` instruction.

---

## 10. Obfuscation Architecture

### Goals and Threat Model

The obfuscation system targets two categories of static analysis:

| Threat | Mitigation |
|--------|-----------|
| Hash-based AV signatures | Polymorphic build-ID (different hash every build) |
| String-based detection rules | XOR-encrypted string literals |
| Pattern-based binary signatures | Entropy injection (different data section every build) |
| Source-level analysis | Custom syntax (`.jk` files are not recognisable by AV parsers) |

### XOR Key Management

```
Compile time:
  key = random.randint(1, 255)             ← new key per build
  each .jk_str.* global XOR-encrypted with key
  _jocky_xor_key global set to key

Runtime (native .exe):
  jk_xordecrypt reads extern _jocky_xor_key
  XORs each byte of the encrypted global back
  Returns heap-allocated plaintext buffer
```

The choice of a single module-level key (rather than per-string) means the `jk_xordecrypt` signature only needs the string pointer and length — no key argument — keeping the LLVM IR calling convention identical between obfuscated and non-obfuscated builds.

### Polymorphism Proof

The `compute_hash` utility in `passes.py` computes the SHA-256 of the compiled `.o` file. Running the same compile command twice will produce two `.o` files with different SHA-256 values because the build-ID and entropy globals change each time.

---

## 11. Module Dependencies

```
jocky.py
  └── imports: jocky_terminal (when no args)
  └── imports: jocky.{lexer, parser, semantic, codegen, passes} (direct commands)
  └── subprocess: compiler.py (run / build commands)

jocky_terminal.py
  └── imports: jocky.{lexer, parser, semantic, codegen, passes} (inspect)
  └── subprocess: compiler.py (run / build commands)

compiler/compiler.py
  └── imports: jocky.lexer, jocky.parser, jocky.semantic,
               jocky.codegen, jocky.passes, jocky.stdlib
  └── uses: llvmlite.ir, llvmlite.binding, subprocess (gcc)

jocky/lexer.py
  └── imports: jocky.tokens

jocky/parser.py
  └── imports: jocky.tokens, jocky.ast_nodes

jocky/semantic.py
  └── imports: jocky.ast_nodes, jocky.symbol_table

jocky/codegen.py
  └── imports: jocky.ast_nodes, llvmlite.ir

jocky/passes.py
  └── imports: llvmlite.ir, random, hashlib

jocky/stdlib.py
  └── imports: ctypes, llvmlite.binding

compiler/stdlib/forensics.c
  └── no Python dependencies (pure C, linked by gcc)
```

### External Dependencies

| Dependency | Version | Purpose |
|------------|---------|---------|
| `llvmlite` | 0.43+ | LLVM IR builder and MCJIT engine |
| `rich` | 13+ | TUI rendering (optional; plain fallback exists) |
| MinGW gcc | any | Native binary linking (`gcc` on PATH or at `C:\mingw64\bin\gcc.exe`) |
| Python | 3.10+ | Compiler runtime |
