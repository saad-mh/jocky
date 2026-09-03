#include "jocky/codegen/ObjectEmitter.h"

#include "jocky/Support/Diagnostic.h"

#include <llvm/ADT/Twine.h>
#include <llvm/IR/LegacyPassManager.h>
#include <llvm/IR/Module.h>
#include <llvm/MC/TargetRegistry.h>
#include <llvm/Support/CodeGen.h>
#include <llvm/Support/FileSystem.h>
#include <llvm/Support/TargetSelect.h>
#include <llvm/Support/raw_ostream.h>
#include <llvm/Target/TargetMachine.h>
#include <llvm/Target/TargetOptions.h>
#include <llvm/TargetParser/Host.h>

#include <optional>
#include <string>
#include <system_error>

namespace jocky::codegen {

void initializeNativeTarget() {
    llvm::InitializeNativeTarget();
    llvm::InitializeNativeTargetAsmPrinter();  // needed to emit machine code
    llvm::InitializeNativeTargetAsmParser();   // harmless; only used to read .s
}

std::unique_ptr<llvm::TargetMachine> createHostTargetMachine(
    llvm::Module &module, OptLevel level, DiagnosticEngine &diags) {
    const std::string triple = llvm::sys::getDefaultTargetTriple();

    std::string lookupError;
    const llvm::Target *target =
        llvm::TargetRegistry::lookupTarget(triple, lookupError);
    if (!target) {
        diags.error({}, llvm::Twine("no backend for target triple '") + triple +
                            "': " + lookupError);
        return nullptr;
    }

    const llvm::CodeGenOptLevel codegenLevel =
        (level == OptLevel::O1) ? llvm::CodeGenOptLevel::Default
                                : llvm::CodeGenOptLevel::None;

    llvm::TargetOptions options;
    std::unique_ptr<llvm::TargetMachine> machine(target->createTargetMachine(
        triple, llvm::sys::getHostCPUName(), /*Features=*/"", options,
        std::optional<llvm::Reloc::Model>(llvm::Reloc::PIC_),
        /*CodeModel=*/std::nullopt, codegenLevel));
    if (!machine) {
        diags.error({}, llvm::Twine("could not create a target machine for '") +
                            triple + "'");
        return nullptr;
    }

    module.setTargetTriple(triple);
    module.setDataLayout(machine->createDataLayout());
    return machine;
}

bool emitObjectFile(llvm::Module &module, llvm::TargetMachine &machine,
                    llvm::StringRef outputPath, DiagnosticEngine &diags) {
    std::error_code ec;
    llvm::raw_fd_ostream out(outputPath, ec, llvm::sys::fs::OF_None);
    if (ec) {
        diags.error({}, llvm::Twine("cannot open '") + outputPath +
                            "' for writing: " + ec.message());
        return false;
    }

    // TargetMachine::addPassesToEmitFile still requires the legacy pass manager
    // in LLVM 18 (there is no new-pass-manager path for full code generation).
    // This is the only spot in JOCKY that uses it.
    llvm::legacy::PassManager pm;
    if (machine.addPassesToEmitFile(pm, out, /*DwoOut=*/nullptr,
                                    llvm::CodeGenFileType::ObjectFile)) {
        diags.error({}, "this target cannot emit an object file directly");
        return false;
    }
    pm.run(module);
    out.flush();
    return true;
}

}  // namespace jocky::codegen
