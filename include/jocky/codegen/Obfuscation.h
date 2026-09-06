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

// --- the registry ---------------------------------------------------

// Appends the obfuscation passes selected by `obf` to `mpm`, in a fixed order.
// An empty `obf.passes` selects every pass. Unknown names are reported on
// stderr and skipped. If `obf.seed` is 0 a seed is derived at run time (and
// echoed when `obf.verbose`). Called from runTransformPipeline().
void addObfuscationPasses(llvm::ModulePassManager &mpm,
                          const ObfuscationOptions &obf);

}  // namespace jocky::codegen

#endif  // JOCKY_CODEGEN_OBFUSCATION_H
