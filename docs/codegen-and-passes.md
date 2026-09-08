# Codegen and the transform pipeline

This document is about `src/codegen/` and, in particular, the one function that
is the intended place for future IR transforms.

## How lowering works

`CodeGen::lowerModule` walks the AST and builds an `llvm::Module` with LLVM's
`IRBuilder`. The rules are intentionally boring:

- **One value type.** Everything is `i64`.
- **Variables are memory.** `let x = e;` emits `%x = alloca i64` (in the
  function's entry block) and `store`. Reading `x` emits `load`. Assignment
  emits `store`. No hand-written SSA, no phi nodes.
- **Control flow is explicit blocks.** `check` creates `if.then`, optionally
  `if.else`, and `if.cont`, and wires branches between them. `while` creates
  `while.cond`, `while.body`, `while.end`. After lowering a block, if it has no
  terminator yet, a branch to the continuation block is added; at the end of a
  function, a missing terminator becomes `ret i64 0`.
- **Comparisons.** As a condition, a comparison lowers straight to an `i1` that
  the branch reads. As a value (`let b = a < c;`), the `i1` is zero-extended
  back to `i64`.
- **`print`.** `getOrDeclarePrintf` declares `i32 @printf(ptr, ...)`.
  `internFormat` creates the `"%lld\n"` / `"%s\n"` global once per module.
  A string argument's bytes are interned as another private global.

Run `jocky build --emit-llvm examples/fib.jk` to see typical output.

Because the loads and stores are left in place, `-O0` output is verbose but
correct. `-O1` runs `mem2reg` (among much else) and the variables become plain
SSA values.

## The transform pipeline seam

    // include/jocky/codegen/PassPipeline.h
    void runTransformPipeline(llvm::Module &module,
                              llvm::TargetMachine *machine,
                              OptLevel level,
                              const ObfuscationOptions &obf = {});

Every IR/MIR transform goes through this one function. The driver calls it once,
after lowering and before object emission (and, for `--emit-llvm` with `-O1` or
`--obfuscate`, before printing).

The body, in order:

- `OptLevel::O0` starts from an empty `ModulePassManager` - a valid no-op.
  `OptLevel::O1` starts from `PassBuilder::buildPerModuleDefaultPipeline(O1)`.
  (`buildPerModuleDefaultPipeline` asserts if given `O0`, which is why `O0` uses
  an empty manager rather than asking for an "`O0` pipeline".)
- If `obf.enabled`, `addObfuscationPasses()` appends JOCKY's obfuscation passes
  **after** the `-O1` pipeline, so its cleanup (DCE, instcombine, ...) does not
  simplify them back out.
- `mpm.run(module, mam)`.
- In debug builds, when obfuscation ran, the module is re-verified; a failure is
  a pass bug and aborts rather than emitting a broken object.

## The obfuscation passes

`--obfuscate` (optionally `--obfuscate=<a,b,...>` for a subset) turns on the
passes in `src/codegen/Obfuscation.cpp`. `--obf-seed <n>` pins the RNG so a build
is reproducible; with no seed one is derived at run time, and `-v` echoes it.

Registered, in the order they run when all are on:

| name       | what it does                                                                  | reaches the binary? |
|------------|------------------------------------------------------------------------------|---------------------|
| `split`    | cuts each large block in two at a random point (`jk.split`)                  | no (backend re-fuses straight-line blocks) |
| `flatten`  | replaces each function's CFG with one `switch` dispatch loop over a state var (`jk.sv` / `jk.dispatch` / `jk.loopend`); LLVM's `reg2mem` runs first so no value escapes its block | yes |
| `indirect` | direct calls to user functions become a load of `jk.fp.<name>` (`ptrtoint(@f) + key`), a subtract, and an indirect call; `printf` etc. stay direct | yes |
| `junk`     | inserts 1-3 unused `%jk.*` i64 instructions into every basic block           | no (dead SSA; `-O0` backend drops it) |

`split` and `junk` change only the IR (useful when the IR itself is the
artifact, e.g. `--emit-llvm`); `flatten` and `indirect` change the emitted
machine code. Obfuscation runs *after* the `-O1` pipeline, so `-O1 --obfuscate`
optimises first and then obfuscates.

## Adding a pass

A new-pass-manager pass is a small struct with a
`PreservedAnalyses run(Module&, ModuleAnalysisManager&)` method
(`llvm::PassInfoMixin` gives you the boilerplate). To add one:

1. Declare it in `include/jocky/codegen/Obfuscation.h` and implement it in
   `src/codegen/Obfuscation.cpp` (already in the `src/CMakeLists.txt` source
   list).
2. Add its name to `kKnownPasses` and to the dispatch at the bottom of
   `addObfuscationPasses()`.
3. Add a `test/frontend/obfuscate_<name>.jk` that checks the IR with and without
   the pass, and asserts a fixed `--obf-seed` is reproducible.

The driver passes the `TargetMachine` (when it has one) into
`runTransformPipeline`, so target-aware passes have what they need.
