#include "jocky/codegen/PassPipeline.h"

#include <llvm/IR/PassManager.h>
#include <llvm/Passes/OptimizationLevel.h>
#include <llvm/Passes/PassBuilder.h>

namespace jocky::codegen {

void runTransformPipeline(llvm::Module &module, llvm::TargetMachine *machine,
                          OptLevel level) {
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

    // --- Future randomizing / obfuscation passes are added here. ---
    // e.g. mpm.addPass(jocky::RandomizedIRTransformPass(perBuildSeed()));

    mpm.run(module, mam);
}

}  // namespace jocky::codegen
