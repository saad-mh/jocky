#include "jocky/codegen/Obfuscation.h"

#include <llvm/ADT/STLExtras.h>  // llvm::is_contained
#include <llvm/ADT/SmallVector.h>
#include <llvm/ADT/StringRef.h>
#include <llvm/IR/BasicBlock.h>
#include <llvm/IR/Constants.h>
#include <llvm/IR/Function.h>
#include <llvm/IR/IRBuilder.h>
#include <llvm/IR/Module.h>
#include <llvm/IR/NoFolder.h>
#include <llvm/IR/Type.h>
#include <llvm/Support/raw_ostream.h>

#include <array>
#include <random>

namespace jocky::codegen {

namespace {

// Every obfuscation pass name, in the order they run when all are requested.
// Keep in sync with the dispatch at the bottom of addObfuscationPasses().
constexpr std::array<llvm::StringRef, 1> kKnownPasses = {llvm::StringRef("junk")};

// A run-time seed for when the user did not pin one with --obf-seed.
std::uint64_t deriveSeed() {
    std::random_device rd;
    return (static_cast<std::uint64_t>(rd()) << 32) ^
           static_cast<std::uint64_t>(rd());
}

}  // namespace

llvm::PreservedAnalyses JunkInsertionPass::run(llvm::Module &m,
                                               llvm::ModuleAnalysisManager &) {
    // Salt the caller's seed so this pass has its own RNG stream, distinct from
    // any other pass handed the same base seed.
    std::mt19937_64 rng(seed_ ^ 0x6a6b00006a756e6bULL /* "jk\0\0junk" */);
    llvm::Type *i64 = llvm::Type::getInt64Ty(m.getContext());
    bool changed = false;

    for (llvm::Function &fn : m) {
        if (fn.isDeclaration()) continue;

        for (llvm::BasicBlock &bb : fn) {
            llvm::Instruction *term = bb.getTerminator();
            if (!term) continue;  // malformed block; leave it for the verifier

            // NoFolder: a chain of constants would otherwise be folded to a
            // single constant before any instruction is emitted. The junk is
            // meant to be real instructions.
            llvm::IRBuilder<llvm::NoFolder> b(term);  // ahead of the terminator

            // Anchor the chain on an i64 value already computed in this block
            // when there is one, so the junk is not pure constant arithmetic.
            llvm::Value *v = nullptr;
            for (llvm::Instruction &inst : bb) {
                if (&inst == term) break;
                if (inst.getType() == i64) v = &inst;
            }
            if (!v) v = llvm::ConstantInt::get(i64, rng());

            const unsigned n = 1 + static_cast<unsigned>(rng() % 3);  // 1..3
            for (unsigned i = 0; i < n; ++i) {
                llvm::Value *k = llvm::ConstantInt::get(i64, rng() | 1ULL);
                switch (rng() % 3) {
                case 0:  v = b.CreateAdd(v, k, "jk.add"); break;
                case 1:  v = b.CreateXor(v, k, "jk.xor"); break;
                default: v = b.CreateMul(v, k, "jk.mul"); break;
                }
            }
            changed = true;
        }
    }

    return changed ? llvm::PreservedAnalyses::none()
                   : llvm::PreservedAnalyses::all();
}

void addObfuscationPasses(llvm::ModulePassManager &mpm,
                          const ObfuscationOptions &obf) {
    llvm::SmallVector<llvm::StringRef, 8> requested;
    if (!obf.passes.empty())
        llvm::StringRef(obf.passes).split(requested, ',', /*MaxSplit=*/-1,
                                          /*KeepEmpty=*/false);

    for (llvm::StringRef name : requested) {
        if (!llvm::is_contained(kKnownPasses, name))
            llvm::errs() << "jocky: warning: unknown obfuscation pass '" << name
                         << "'\n";
    }

    const auto wanted = [&](llvm::StringRef name) {
        return requested.empty() || llvm::is_contained(requested, name);
    };

    const std::uint64_t seed = obf.seed ? obf.seed : deriveSeed();
    if (obf.verbose)
        llvm::errs() << "jocky: obfuscation seed " << seed << '\n';

    // --- dispatch: keep in sync with kKnownPasses -------------------
    if (wanted("junk"))
        mpm.addPass(JunkInsertionPass(seed));
}

}  // namespace jocky::codegen
