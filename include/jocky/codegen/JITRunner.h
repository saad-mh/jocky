// In-memory compilation and execution via LLVM ORC JIT.
//
// runInMemory() is the --run path: the module and its context are compiled
// directly to native code in an anonymous executable region, "main" is looked
// up and called, and the process never writes a .obj or .exe to disk.

#ifndef JOCKY_CODEGEN_JITRUNNER_H
#define JOCKY_CODEGEN_JITRUNNER_H

#include <memory>

namespace llvm {
class LLVMContext;
class Module;
}  // namespace llvm

namespace jocky::driver {
struct Options;
}  // namespace jocky::driver

namespace jocky::codegen {

// Compiles `module` with LLJIT, calls "main", and returns its exit code.
// Both `module` and `ctx` are consumed — the JIT owns them for the duration.
// Host-process symbols (jkf_*, libc, etc.) are visible to the JIT'd code via
// DynamicLibrarySearchGenerator::GetForCurrentProcess.
int runInMemory(std::unique_ptr<llvm::Module> module,
                std::unique_ptr<llvm::LLVMContext> ctx,
                const jocky::driver::Options &opts);

}  // namespace jocky::codegen

#endif  // JOCKY_CODEGEN_JITRUNNER_H
