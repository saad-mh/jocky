// The single place where IR/MIR transform passes run.
//
// Everything that wants to transform the module - today just "run LLVM's
// standard -O1 pipeline, or nothing" - goes through runTransformPipeline().
// Keeping it to one function means a future custom pass (for example the
// per-build randomizing passes in the project's long-term plan) can be added
// here without touching any caller.

#ifndef JOCKY_CODEGEN_PASSPIPELINE_H
#define JOCKY_CODEGEN_PASSPIPELINE_H

namespace llvm {
class Module;
class TargetMachine;
}  // namespace llvm

namespace jocky::codegen {

enum class OptLevel {
    O0,  // no transforms
    O1,  // LLVM's standard -O1 module pipeline
};

// Runs the transform pipeline for `level` over `module` in place.
// `machine` may be null (for example when only printing IR); it is used for
// target-aware tuning when present.
void runTransformPipeline(llvm::Module &module, llvm::TargetMachine *machine,
                          OptLevel level);

}  // namespace jocky::codegen

#endif  // JOCKY_CODEGEN_PASSPIPELINE_H
