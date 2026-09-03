# Codegen and the transform pipeline

This document is about `src/codegen/` and, in particular, the one function that
is the intended place for future IR transforms.

## How lowering works

`CodeGen::lowerModule` walks the AST and builds an `llvm::Module` with LLVM's
`IRBuilder`. The rules are intentionally boring:

- **One value type.** Everything is `i64`.
- **Variables are memory.** `var x = e;` emits `%x = alloca i64` (in the
  function's entry block) and `store`. Reading `x` emits `load`. Assignment
  emits `store`. No hand-written SSA, no phi nodes.
- **Control flow is explicit blocks.** `if` creates `if.then`, optionally
  `if.else`, and `if.cont`, and wires branches between them. `while` creates
  `while.cond`, `while.body`, `while.end`. After lowering a block, if it has no
  terminator yet, a branch to the continuation block is added; at the end of a
  function, a missing terminator becomes `ret i64 0`.
- **Comparisons.** As a condition, a comparison lowers straight to an `i1` that
  the branch reads. As a value (`var b = a < c;`), the `i1` is zero-extended
  back to `i64`.
- **`print`.** `getOrDeclarePrintf` declares `i32 @printf(ptr, ...)`.
  `internFormat` creates the `"%lld\n"` / `"%s\n"` global once per module.
  A string argument's bytes are interned as another private global.

Run `jocky build --emit-llvm examples/fib.jky` to see typical output.

Because the loads and stores are left in place, `-O0` output is verbose but
correct. `-O1` runs `mem2reg` (among much else) and the variables become plain
SSA values.

## The transform pipeline seam

    // include/jocky/codegen/PassPipeline.h
    void runTransformPipeline(llvm::Module &module,
                              llvm::TargetMachine *machine,
                              OptLevel level);

Every IR/MIR transform goes through this one function. The driver calls it once,
after lowering and before object emission (and, for `--emit-llvm -O1`, before
printing). Callers pass only an `OptLevel`.

Today the body is short:

- `OptLevel::O0` runs an empty `ModulePassManager` - a valid no-op.
- `OptLevel::O1` runs `PassBuilder::buildPerModuleDefaultPipeline(O1)`.

`buildPerModuleDefaultPipeline` asserts if given `O0`, which is why `O0` uses an
empty manager rather than asking the builder for an "`O0` pipeline".

## Adding a custom pass later

The project's longer-term goal includes passes that make each build's machine
code structurally different. When that work starts, it goes **inside**
`runTransformPipeline`, at the marked comment, and nothing else changes:

    llvm::ModulePassManager mpm;
    if (level == OptLevel::O1)
        mpm = pb.buildPerModuleDefaultPipeline(llvm::OptimizationLevel::O1);

    // --- Future randomizing / obfuscation passes are added here. ---
    mpm.addPass(jocky::RandomizedIRTransformPass(perBuildSeed()));

    mpm.run(module, mam);

A new-pass-manager pass is a small struct with a
`PreservedAnalyses run(Module&, ModuleAnalysisManager&)` method. Keep it in
`src/codegen/`, add it to the source list in `src/CMakeLists.txt`, and give it a
frontend test that checks the IR before and after.

The driver already passes the `TargetMachine` (when it has one) into
`runTransformPipeline`, so target-aware passes have what they need.
