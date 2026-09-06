#include "jocky/codegen/PassPipeline.h"

#include "jocky/codegen/Obfuscation.h"

#include <llvm/IR/PassManager.h>
#include <llvm/IR/Verifier.h>
#include <llvm/Passes/OptimizationLevel.h>
#include <llvm/Passes/PassBuilder.h>
#include <llvm/Support/ErrorHandling.h>
#include <llvm/Support/raw_ostream.h>

namespace jocky::codegen {

void runTransformPipeline(llvm::Module &module, llvm::TargetMachine *machine,
                          OptLevel level, const ObfuscationOptions &obf) {
    // Standard new-pass-manager setup.
    llvm::PassBuilder pb(machine);

    llvm::LoopAnalysisManager lam;
    llvm::FunctionAnalysisManager fam;
    llvm::CGSCCAnalysisManager cgam;
    llvm::ModuleAnalysisManager mam;

    pb.registerModuleAnalyses(mam);
    pb.registerCGSCCAnalyses(cgam);
    pb.registerFunctionAnalyses(fam);
    pb.registerLoopAnalyses(lam);
    pb.crossRegisterProxies(lam, fam, cgam, mam);

    llvm::ModulePassManager mpm;  // an empty pipeline is a valid no-op (O0)
    if (level == OptLevel::O1) {
        // buildPerModuleDefaultPipeline() asserts if handed O0, which is why
        // the O0 path above leaves `mpm` empty instead of calling it.
        mpm = pb.buildPerModuleDefaultPipeline(llvm::OptimizationLevel::O1);
    }

    // Obfuscation passes run last - after any -O1 cleanup - so their inserted
    // instructions and rewritten control flow are not simplified back out.
    if (obf.enabled)
        addObfuscationPasses(mpm, obf);

    mpm.run(module, mam);

#ifndef NDEBUG
    // A failed verify here means an obfuscation pass has a bug (the module was
    // already verified before lowering handed it over). Catch it loudly in
    // debug builds rather than emitting a broken object file.
    if (obf.enabled && llvm::verifyModule(module, &llvm::errs()))
        llvm::report_fatal_error("jocky: an obfuscation pass produced invalid IR");
#endif
}

}  // namespace jocky::codegen
