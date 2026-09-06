// JOCKY's own IR obfuscation passes and the small registry that selects them.
//
// These are new-pass-manager module passes. They are wired into the compiler at
// exactly one point - runTransformPipeline() in PassPipeline.cpp - which calls
// addObfuscationPasses() when `--obfuscate` was given. Nothing else needs to
// know they exist.
//
// Each pass takes a 64-bit seed so a build is reproducible: the same source and
// the same `--obf-seed` produce the same binary, while a different seed (the
// default, derived at run time) produces a structurally different one.

#ifndef JOCKY_CODEGEN_OBFUSCATION_H
#define JOCKY_CODEGEN_OBFUSCATION_H

#include "jocky/codegen/PassPipeline.h"  // ObfuscationOptions

#include <cstdint>

#include <llvm/IR/PassManager.h>

namespace jocky::codegen {

// --- individual passes ------------------------------------------------

// Inserts one to three unused ("junk") integer instructions into every basic
// block of every user-defined function. The junk is valid SSA whose result is
// never read, so the module still verifies; it exists to change instruction
// counts and the local opcode mix, and to exercise the obfuscation seam end to
// end. This is deliberately the simplest pass - it does not yet defend against
// a later dead-code-elimination pass, which is fine because JOCKY's -O0
// pipeline runs none and its -O1 obfuscation runs *after* the -O1 cleanup.
// Structural passes (block splitting, control-flow flattening, call
// indirection) come next and change code that is actually observed.
class JunkInsertionPass : public llvm::PassInfoMixin<JunkInsertionPass> {
public:
    explicit JunkInsertionPass(std::uint64_t seed) : seed_(seed) {}
    llvm::PreservedAnalyses run(llvm::Module &m, llvm::ModuleAnalysisManager &);

private:
    std::uint64_t seed_;
};

// Splits each sufficiently large basic block once, at a random interior point,
// into two blocks joined by an unconditional branch (the new block is named
// `jk.split`). This roughly doubles the block count of straight-line code and
// is the primitive that control-flow flattening builds on. On its own the -O0
// backend lays the halves out consecutively, so the machine code is unchanged;
// its value is structural (more blocks, more labels in the IR / CFG).
class BlockSplittingPass : public llvm::PassInfoMixin<BlockSplittingPass> {
public:
    explicit BlockSplittingPass(std::uint64_t seed) : seed_(seed) {}
    llvm::PreservedAnalyses run(llvm::Module &m, llvm::ModuleAnalysisManager &);

private:
    std::uint64_t seed_;
};

// Flattens each function's control-flow graph: every original basic block
// becomes a case of one `switch` (`jk.dispatch`) driven by a state variable
// (`jk.sv`), and each block, instead of branching to its successor, stores that
// successor's number and jumps back to the dispatcher (`jk.loopend`). The
// linear order of the original blocks is destroyed - a decompiler sees one big
// loop. `ret` blocks keep their terminator (they exit the loop). Single-block
// functions are left alone. Requires LLVM's reg2mem to have run first (the
// registry adds it) so no value is used outside its block and flattening cannot
// break SSA dominance.
class FlatteningPass : public llvm::PassInfoMixin<FlatteningPass> {
public:
    explicit FlatteningPass(std::uint64_t seed) : seed_(seed) {}
    llvm::PreservedAnalyses run(llvm::Module &m, llvm::ModuleAnalysisManager &);

private:
    std::uint64_t seed_;
};

// Rewrites direct calls to user-defined functions into indirect calls: the
// callee address is kept in a private global (`jk.fp.<name>`) and loaded at the
// call site, so the IR no longer carries a direct call edge and the backend
// emits an indirect call. Calls to declarations and intrinsics (e.g. printf)
// are left alone. This one does survive to the binary.
class CallIndirectionPass : public llvm::PassInfoMixin<CallIndirectionPass> {
public:
    explicit CallIndirectionPass(std::uint64_t seed) : seed_(seed) {}
    llvm::PreservedAnalyses run(llvm::Module &m, llvm::ModuleAnalysisManager &);

private:
    std::uint64_t seed_;
};

// --- the registry ---------------------------------------------------

// Appends the obfuscation passes selected by `obf` to `mpm`, in a fixed order.
// An empty `obf.passes` selects every pass. Unknown names are reported on
// stderr and skipped. If `obf.seed` is 0 a seed is derived at run time (and
// echoed when `obf.verbose`). Called from runTransformPipeline().
void addObfuscationPasses(llvm::ModulePassManager &mpm,
                          const ObfuscationOptions &obf);

}  // namespace jocky::codegen

#endif  // JOCKY_CODEGEN_OBFUSCATION_H
