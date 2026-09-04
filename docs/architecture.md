# JOCKY compiler architecture

This document walks through what happens when you run

    jocky build hello.jk -o hello.exe

Each stage is a separate part of the source tree so you can work on one without
reading the others. The stages run in order; if a stage reports an error the
driver stops and the later stages do not run.

## 1. Driver (`src/driver/`)

The entry point. `main.cpp` turns the command line into an `Options` value.
`Driver::run` then calls each stage in turn and decides what to do based on the
sub-command (`build`, `lex`, `parse`) and flags (`--emit-llvm`, `--emit-obj`,
and so on). It also owns the small jobs around the edges: reading the input
file, choosing the output file name, deleting the temporary object file.

## 2. Lexer (`src/lexer/`)

Input: the raw source text. Output: a flat list of *tokens* - the smallest
meaningful pieces, like the keyword `func`, the number `42`, the identifier
`total`, or the symbol `<=`.

The lexer is hand-written. It reads the text one character at a time, tracks the
line and column so later error messages can point at the right spot, skips
whitespace and `//` comments, and recognizes the six keywords. If it hits
something it cannot make sense of (a stray character, a string with no closing
quote, a number too big for 64 bits) it records an error and keeps going, so one
run finds every problem rather than stopping at the first.

## 3. Parser (`src/parser/`)

Input: the token list. Output: an *abstract syntax tree* (AST) - a tree of
objects that mirrors the structure of the program (this function contains this
block, which contains this `if`, whose condition is this comparison...).

The parser is *recursive descent*: there is one function per grammar rule
(`parseStatement`, `parseExpr`, and so on) and they call each other the same way
the grammar nests. Operator precedence (so `a + b * c` groups as `a + (b * c)`)
is handled by layering the expression functions from lowest precedence to
highest. On a syntax error the parser reports it, skips ahead to the next likely
restart point (a `;`, a `}`, or a statement keyword), and continues.

The AST node types live in `src/ast/`. An `ast::Module` owns every node; the
nodes point at each other with plain pointers and are all freed together when
the module is destroyed.

## 4. Codegen - lowering (`src/codegen/CodeGen.cpp`)

Input: the AST. Output: an `llvm::Module` - LLVM's in-memory representation of a
program, made of functions, basic blocks, and instructions ("LLVM IR").

This stage also does the small amount of checking v0 needs: every name must be
declared, calls must pass the right number of arguments, and a string literal may
only be used as a direct argument to `print`.

The lowering is deliberately simple. Every JOCKY value is a 64-bit integer.
Every local variable is a stack slot: declaring it emits an `alloca`, reading it
emits a `load`, assigning to it emits a `store`. We do not try to be clever;
`-O1` can clean this up later, and `-O0` leaves it as-is, which is still correct.
`if` and `while` are built by hand out of basic blocks and branches. `print` is a
builtin: the compiler declares C's `printf`, creates a format string
(`"%lld\n"` for integers, `"%s\n"` for strings), and emits a call.

You can see the result with `jocky build --emit-llvm hello.jk`.

## 5. Codegen - transform pipeline (`src/codegen/PassPipeline.cpp`)

`runTransformPipeline` is the single place where IR transform passes run. Today
it does nothing at `-O0` and runs LLVM's standard `-O1` pipeline at `-O1`. It is
kept to one function on purpose: the project's longer-term plans include custom
per-build passes, and this is the spot where they will be added, with no change
to any caller. See `codegen-and-passes.md`.

## 6. Codegen - object file (`src/codegen/ObjectEmitter.cpp`)

Input: the `llvm::Module`. Output: a native object file (`.obj` on Windows).

This asks LLVM for a `TargetMachine` describing the machine we are on, records
its details on the module, and then runs LLVM's code generator to turn the IR
into machine code and write it out. This is the one part of JOCKY that uses
LLVM's older "legacy pass manager", because the code generator still requires it.

## 7. Driver - linking (`src/driver/Linker.cpp`)

Input: the object file. Output: a runnable executable.

`link` runs `clang` as a linker driver (`clang hello.obj -o hello.exe
-fuse-ld=lld`). We go through `clang` because it already knows how to find the
platform's C runtime and startup code; `-fuse-ld=lld` tells it to use LLVM's own
linker, `lld`. This is a seam: a future version could call `lld` in-process
instead, and nothing else would change.
