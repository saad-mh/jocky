# JOCKY compiler architecture

This document walks through what happens when you run

    jocky build hello.jk -o hello.exe

Each stage is a separate part of the source tree so you can work on one without
reading the others. The stages run in order; if a stage reports an error the
driver stops and the later stages do not run.

## 1. Driver (`src/driver/`)

The entry point. `main.cpp` turns the command line into an `Options` value.
`Driver::run` then calls each stage in turn and decides what to do based on the
sub-command (`build`, `check`, `lex`, `parse`) and flags (`--emit-llvm`,
`--emit-obj`, and so on). It also owns the small jobs around the edges: reading
the input file, choosing the output file name, deleting the temporary object
file.

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
block, which contains this `check`, whose condition is this comparison...).

The parser is *recursive descent*: there is one function per grammar rule
(`parseStatement`, `parseExpr`, and so on) and they call each other the same way
the grammar nests. Operator precedence (so `a + b * c` groups as `a + (b * c)`)
is handled by layering the expression functions from lowest precedence to
highest. On a syntax error the parser reports it, skips ahead to the next likely
restart point (a `;`, a `}`, or a statement keyword), and continues.

The AST node types live in `src/ast/`. An `ast::Module` owns every node; the
nodes point at each other with plain pointers and are all freed together when
the module is destroyed.

## 4. Semantic analysis (`src/sema/`)

Input: the AST. Output: the same AST, checked (and, as the type system grows,
annotated with a resolved `ast::Type` on every expression).

This is where the front end's meaning-level rules live: every name must resolve,
every call must match a signature, and - from the L0 type-system milestone on -
every expression must have a type its context accepts. It is a two-pass walk:
first register every function's name and arity so calls resolve regardless of
source order, then walk each body in source order. The scope model is v0's: no
nested scopes, a `let` visible for the rest of its function once its initializer
has been checked.

`jocky check <file>.jk` runs the pipeline up to and including this stage and
then stops - handy for editor integration and fast feedback. `build` runs it
too, and only reaches codegen if it reported nothing.

## 5. Codegen - lowering (`src/codegen/CodeGen.cpp`)

Input: the checked AST. Output: an `llvm::Module` - LLVM's in-memory
representation of a program, made of functions, basic blocks, and instructions
("LLVM IR").

Codegen trusts sema: it does no name lookup or argument-count checking of its
own. The few `error(...)` calls it still contains are marked "internal:" and
only fire on a compiler bug.

The lowering is deliberately simple. Every JOCKY value is a 64-bit integer.
Every local variable is a stack slot: declaring it emits an `alloca`, reading it
emits a `load`, assigning to it emits a `store`. We do not try to be clever;
`-O1` can clean this up later, and `-O0` leaves it as-is, which is still correct.
`check` and `while` are built by hand out of basic blocks and branches. `print` is a
builtin: the compiler declares C's `printf`, creates a format string
(`"%lld\n"` for integers, `"%s\n"` for strings), and emits a call.

You can see the result with `jocky build --emit-llvm hello.jk`.

## 6. Codegen - transform pipeline (`src/codegen/PassPipeline.cpp`)

`runTransformPipeline` is the single place where IR transform passes run. It does
nothing at `-O0`, runs LLVM's standard `-O1` pipeline at `-O1`, and - when
`--obfuscate` was given - appends JOCKY's own obfuscation passes after that. It
is kept to one function on purpose, so new per-build passes can be added with no
change to any caller. See `codegen-and-passes.md`.

## 7. Codegen - object file (`src/codegen/ObjectEmitter.cpp`)

Input: the `llvm::Module`. Output: a native object file (`.obj` on Windows).

This asks LLVM for a `TargetMachine` describing the machine we are on, records
its details on the module, and then runs LLVM's code generator to turn the IR
into machine code and write it out. This is the one part of JOCKY that uses
LLVM's older "legacy pass manager", because the code generator still requires it.

## 8. Driver - linking (`src/driver/Linker.cpp`)

Input: the object file. Output: a runnable executable.

`link` runs `clang` as a linker driver (`clang hello.obj -o hello.exe
-fuse-ld=lld`). We go through `clang` because it already knows how to find the
platform's C runtime and startup code; `-fuse-ld=lld` tells it to use LLVM's own
linker, `lld`. This is a seam: a future version could call `lld` in-process
instead, and nothing else would change.
