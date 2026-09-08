#include "jocky/codegen/JITRunner.h"
#include "jocky/driver/Options.h"

#include <llvm/ExecutionEngine/Orc/ExecutionUtils.h>
#include <llvm/ExecutionEngine/Orc/LLJIT.h>
#include <llvm/ExecutionEngine/Orc/ThreadSafeModule.h>
#include <llvm/IR/LLVMContext.h>
#include <llvm/IR/Module.h>
#include <llvm/Support/Error.h>
#include <llvm/Support/raw_ostream.h>

#include <memory>

namespace jocky::codegen {

int runInMemory(std::unique_ptr<llvm::Module> module,
                std::unique_ptr<llvm::LLVMContext> ctx,
                const jocky::driver::Options &opts) {
    auto jitOrErr = llvm::orc::LLJITBuilder().create();
    if (!jitOrErr) {
        llvm::errs() << "jocky: JIT init failed: "
                     << llvm::toString(jitOrErr.takeError()) << '\n';
        return 1;
    }
    auto &jit = *jitOrErr;

    // Make every symbol exported by the host process (jkf_* from jockyrt, the
    // C runtime, etc.) visible to the JIT-compiled code.
    auto gen = llvm::orc::DynamicLibrarySearchGenerator::GetForCurrentProcess(
        jit->getDataLayout().getGlobalPrefix());
    if (!gen) {
        llvm::errs() << "jocky: failed to build process symbol search: "
                     << llvm::toString(gen.takeError()) << '\n';
        return 1;
    }
    jit->getMainJITDylib().addGenerator(std::move(*gen));

    if (auto err = jit->addIRModule(
            llvm::orc::ThreadSafeModule(std::move(module), std::move(ctx)))) {
        llvm::errs() << "jocky: failed to add module to JIT: "
                     << llvm::toString(std::move(err)) << '\n';
        return 1;
    }

    auto mainSym = jit->lookup("main");
    if (!mainSym) {
        llvm::errs() << "jocky: JIT lookup for 'main' failed: "
                     << llvm::toString(mainSym.takeError()) << '\n';
        return 1;
    }

    if (opts.verbose)
        llvm::errs() << "jocky: executing in-memory (no disk artifact)\n";

    auto *mainFn = mainSym->toPtr<int (*)()>();
    return mainFn();
}

}  // namespace jocky::codegen
