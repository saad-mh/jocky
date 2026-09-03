// Turning an llvm::Module into a native object file (.o / .obj).
//
// This is the backend half of codegen: it asks LLVM for a TargetMachine that
// describes the host, then runs LLVM's code generator to write machine code.

#ifndef JOCKY_CODEGEN_OBJECTEMITTER_H
#define JOCKY_CODEGEN_OBJECTEMITTER_H

#include "jocky/codegen/PassPipeline.h"  // OptLevel

#include <memory>

#include <llvm/ADT/StringRef.h>

namespace llvm {
class Module;
class TargetMachine;
}  // namespace llvm

namespace jocky {

class DiagnosticEngine;

namespace codegen {

// Registers the host's target backend. Call once before createHostTargetMachine.
void initializeNativeTarget();

// Builds a TargetMachine for the machine we are running on and records its
// target triple and data layout on `module`. Returns null (after reporting via
// `diags`) if the host target is unavailable.
std::unique_ptr<llvm::TargetMachine> createHostTargetMachine(
    llvm::Module &module, OptLevel level, DiagnosticEngine &diags);

// Writes `module` to `outputPath` as a native object file. Returns false (after
// reporting via `diags`) on failure.
bool emitObjectFile(llvm::Module &module, llvm::TargetMachine &machine,
                    llvm::StringRef outputPath, DiagnosticEngine &diags);

}  // namespace codegen
}  // namespace jocky

#endif  // JOCKY_CODEGEN_OBJECTEMITTER_H
