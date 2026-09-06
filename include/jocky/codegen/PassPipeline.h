// The single place where IR/MIR transform passes run.
//
// Everything that wants to transform the module goes through
// runTransformPipeline(): today that is "run LLVM's standard -O1 pipeline, or
// nothing" plus, when `--obfuscate` was given, JOCKY's own obfuscation passes
// (see Obfuscation.h). Keeping it to one function means a new pass can be added
// without touching any caller.

#ifndef JOCKY_CODEGEN_PASSPIPELINE_H
#define JOCKY_CODEGEN_PASSPIPELINE_H

#include <cstdint>
#include <string>

namespace llvm {
class Module;
class TargetMachine;
}  // namespace llvm

namespace jocky::codegen {

enum class OptLevel {
    O0,  // no optimization transforms
    O1,  // LLVM's standard -O1 module pipeline
};

// Selects and configures JOCKY's obfuscation passes. Independent of OptLevel:
// the passes run at -O0, or after the -O1 pipeline so its cleanup does not undo
// them.
struct ObfuscationOptions {
    bool enabled = false;     // --obfuscate
    std::string passes;       // --obfuscate=<a,b,...>; empty => every pass
    std::uint64_t seed = 0;   // --obf-seed <n>; 0 => derived at run time
    bool verbose = false;     // echo the resolved seed to stderr
};

// Runs the transform pipeline for `level` (and `obf`) over `module` in place.
// `machine` may be null (for example when only printing IR); it is used for
// target-aware tuning when present.
void runTransformPipeline(llvm::Module &module, llvm::TargetMachine *machine,
                          OptLevel level, const ObfuscationOptions &obf = {});

}  // namespace jocky::codegen

#endif  // JOCKY_CODEGEN_PASSPIPELINE_H
