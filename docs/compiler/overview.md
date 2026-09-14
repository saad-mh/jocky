# Compiler — Overview

## Why It Exists

The JOCKY compiler exists because scripting languages (Python, PowerShell) are trivially detected and blocked by AV/EDR products, while writing raw C or assembly for every research tool is slow and tedious. The `.jk` language sits in the middle: a high-level syntax that feels like a scripting language but compiles to native Windows executables via LLVM — with automatic obfuscation so no two builds produce the same binary.

The JIT mode (run without linking) removes the need for a C toolchain during iteration. The native build mode produces a standalone `.exe` with no Python dependency.

## What It Does

The compiler takes a `.jk` source file through five pipeline stages:

```
Source (.jk)
    │
    ▼  Stage 1
  Lexer              tokenizes the source into a flat token list
    │
    ▼  Stage 2
  Parser             builds an Abstract Syntax Tree (AST)
    │
    ▼  Stage 3
  SemanticAnalyzer   type-checks the AST, validates signatures
    │
    ▼  Stage 4
  CodeGenerator      lowers the AST to an llvmlite IR module
    │
    ▼  Stage 5
  ObfuscationPasses  runs 4 structural passes over the IR module
    │
    ├─── JIT path:  MCJIT executes the module in-process
    │                stdlib.py registers Python callbacks as LLVM symbols
    │
    └─── Native path: emit object file → gcc links forensics.o → .exe
```

## Pipeline Stages

### Stage 1 — Lexer (`compiler/jocky/lexer.py`)

Converts raw source text into a list of `Token` objects. Each token carries its type (`TokenType` enum), raw value string, line number, and column. Unrecognised characters produce `TokenType.ERROR` tokens rather than raising immediately, so the full token list is always returned and the caller decides how to handle errors.

### Stage 2 — Parser (`compiler/jocky/parser.py`)

A hand-written recursive-descent parser. Consumes the token list and builds an AST whose root is a `Program` node containing one or more `FunctionDef` nodes. Raises `ParseError` on syntax errors.

The parser expects at least one function named `start` — this is the entry point of every `.jk` program.

### Stage 3 — Semantic Analyzer (`compiler/jocky/semantic.py`)

Walks the AST to catch type errors that the parser cannot detect:

- All referenced variables are declared before use.
- Function call argument counts and types match the declaration.
- Return types match the declared function return type.
- The `start` function exists and takes no parameters.

Uses a scoped `SymbolTable` (`compiler/jocky/symbol_table.py`) to track variable bindings across nested blocks.

### Stage 4 — Code Generator (`compiler/jocky/codegen.py`)

Lowers the validated AST to LLVM IR using `llvmlite`. The `CodeGenerator.generate(ast)` method returns an `llvmlite.ir.Module`.

Notable code generation decisions:

- All string literals are emitted as `@.jk_str.N` global byte arrays. These globals are the target of the string-encryption obfuscation pass.
- Every `.jk` program gets a `_jocky_xor_key` global initialised to `0`. The obfuscation pass overwrites it with a random 1–255 value; the native stdlib (`forensics.c`) reads it at runtime to decrypt strings.
- All stdlib functions are emitted as `declare` (external) references. In JIT mode these are resolved against the Python callbacks registered in `stdlib.py`; in native mode they are resolved against `forensics.o`.

### Stage 5 — Obfuscation Passes (`compiler/jocky/passes.py`)

Four IR-level passes run over the `llvmlite.ir.Module`. See [docs/compiler/obfuscation.md](obfuscation.md) for a detailed breakdown.

## JIT vs Native Build

### JIT (run)

```
jocky run scripts/proc_scanner.jk
```

1. Stages 1–5 run in-process.
2. `stdlib.py` registers Python ctypes callbacks for every stdlib function under their LLVM symbol names.
3. `llvmlite.binding.MCJIT` compiles the IR and calls the `start` symbol.
4. No linker, no gcc, no output file. The binary never touches disk.

### Native build (build)

```
jocky build scripts/proc_scanner.jk
```

1. Stages 1–5 run; the obfuscated IR is compiled to a `.o` object file.
2. `compiler.py` generates a per-build import-variation shim: a C file that imports a random subset (4–12) of 30 decoy Win32 API functions. This ensures every binary has a different import hash. The shim also contains the `main()` entry point that calls the `start()` symbol from the `.o`.
3. `gcc` links `forensics.o + shim.o + program.o` into the final `.exe`.
4. Artifacts go to `output/`.

## Output Files

| File | Description |
|---|---|
| `output/<name>.o` | Compiled object (intermediate) |
| `output/<name>.ll` | LLVM IR (only with `--emit-ir` or `jocky ir`) |
| `output/<name>.exe` | Final native binary (Windows) |

## CLI Commands

| Command | Effect |
|---|---|
| `jocky run <file.jk>` | JIT-execute |
| `jocky run <file.jk> --obfuscate` | JIT-execute with obfuscation passes active |
| `jocky run <file.jk> --kernel` | JIT in kernel mode (BYOVD stdlib enabled, simulation) |
| `jocky build <file.jk>` | Compile to native `.exe` (obfuscated) |
| `jocky build <file.jk> --no-obfuscate` | Compile without obfuscation (debug) |
| `jocky ir <file.jk>` | Print clean LLVM IR |
| `jocky ir-obf <file.jk>` | Print obfuscated LLVM IR |
| `jocky tokens <file.jk>` | Print lexer token table |
| `jocky ast <file.jk>` | Print AST tree |
| `jocky inspect <file.jk>` | Full pipeline pass/fail summary |

## Source Files

| File | Role |
|---|---|
| `compiler/compiler.py` | Pipeline orchestrator — `compile_jocky()` entry point |
| `compiler/jocky/lexer.py` | Tokenizer |
| `compiler/jocky/tokens.py` | `TokenType` enum and `KEYWORDS` map |
| `compiler/jocky/parser.py` | Recursive-descent parser |
| `compiler/jocky/ast_nodes.py` | All AST node classes |
| `compiler/jocky/semantic.py` | Type checker |
| `compiler/jocky/symbol_table.py` | Scoped symbol table |
| `compiler/jocky/codegen.py` | LLVM IR code generator |
| `compiler/jocky/passes.py` | Obfuscation passes |
| `compiler/jocky/stdlib.py` | JIT stdlib — Python callbacks registered as LLVM symbols |
| `compiler/stdlib/forensics.c` | Native stdlib — C implementation linked into `.exe` builds |
