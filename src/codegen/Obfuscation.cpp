#include "jocky/codegen/Obfuscation.h"

#include <llvm/ADT/DenseMap.h>
#include <llvm/ADT/STLExtras.h>  // llvm::is_contained, llvm::make_early_inc_range
#include <llvm/ADT/SmallVector.h>
#include <llvm/ADT/StringRef.h>
#include <llvm/IR/BasicBlock.h>
#include <llvm/IR/Constants.h>
#include <llvm/IR/DerivedTypes.h>
#include <llvm/IR/Function.h>
#include <llvm/IR/GlobalVariable.h>
#include <llvm/IR/IRBuilder.h>
#include <llvm/IR/InstrTypes.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/Module.h>
#include <llvm/IR/NoFolder.h>
#include <llvm/IR/PassManager.h>  // createModuleToFunctionPassAdaptor
#include <llvm/IR/Type.h>
#include <llvm/Support/raw_ostream.h>
#include <llvm/Transforms/Scalar/Reg2Mem.h>  // RegToMemPass

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <random>
#include <vector>

namespace jocky::codegen {

namespace {

// Every obfuscation pass name, in the order they run when all are requested.
// Keep in sync with the dispatch at the bottom of addObfuscationPasses().
constexpr std::array<llvm::StringRef, 4> kKnownPasses = {
    llvm::StringRef("split"),     // structural: split blocks first
    llvm::StringRef("flatten"),   // then flatten the (now larger) CFG
    llvm::StringRef("indirect"),  // then hide the call graph
    llvm::StringRef("junk"),      // then pad what remains
};

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

llvm::PreservedAnalyses BlockSplittingPass::run(llvm::Module &m,
                                                llvm::ModuleAnalysisManager &) {
    std::mt19937_64 rng(seed_ ^ 0x6a6b000073706c74ULL /* "jk\0\0splt" */);
    bool changed = false;

    for (llvm::Function &fn : m) {
        if (fn.isDeclaration()) continue;

        // Snapshot the block list: splitBasicBlock() appends new blocks and we
        // only want to consider the originals.
        llvm::SmallVector<llvm::BasicBlock *, 32> blocks;
        for (llvm::BasicBlock &bb : fn) blocks.push_back(&bb);

        for (llvm::BasicBlock *bb : blocks) {
            llvm::Instruction *term = bb->getTerminator();
            if (!term) continue;

            // Candidate split points: everything after leading phis / entry
            // allocas, up to but not including the terminator.
            llvm::SmallVector<llvm::BasicBlock::iterator, 16> points;
            for (auto it = bb->getFirstNonPHIOrDbgOrAlloca(); &*it != term; ++it)
                points.push_back(it);
            if (points.size() < 3) continue;  // too small to be worth splitting

            // Pick an interior point so each half keeps at least one instruction.
            const std::size_t idx = 1 + rng() % (points.size() - 1);
            bb->splitBasicBlock(points[idx], "jk.split");
            changed = true;
        }
    }

    return changed ? llvm::PreservedAnalyses::none()
                   : llvm::PreservedAnalyses::all();
}

namespace {

// Flattens one function. Callers must run RegToMemPass first, so `fn` has no phi
// nodes and no value used outside its defining block - otherwise routing every
// block through the dispatcher would break SSA dominance. Returns true if it
// changed anything.
bool flattenFunction(llvm::Function &fn, std::mt19937_64 &rng) {
    if (fn.size() < 2) return false;  // nothing to flatten in a single block
    for (llvm::BasicBlock &bb : fn)
        if (!bb.phis().empty()) return false;  // reg2mem should have cleared these

    llvm::LLVMContext &ctx = fn.getContext();
    llvm::IntegerType *i32 = llvm::Type::getInt32Ty(ctx);
    llvm::BasicBlock &entry = fn.getEntryBlock();

    // Peel a clean "first real block" off the entry so the entry ends in a
    // single unconditional branch and holds only allocas.
    llvm::BasicBlock *firstReal = entry.splitBasicBlock(
        entry.getFirstNonPHIOrDbgOrAlloca(), "jk.first");

    // Every block except the entry is dispatched through the switch.
    llvm::SmallVector<llvm::BasicBlock *, 32> blocks;
    for (llvm::BasicBlock &bb : fn)
        if (&bb != &entry) blocks.push_back(&bb);
    if (blocks.size() < 2) return true;  // defensive: only the entry split ran

    // A shuffled number per block.
    std::vector<std::uint32_t> nums(blocks.size());
    for (std::size_t i = 0; i < nums.size(); ++i)
        nums[i] = static_cast<std::uint32_t>(i);
    std::shuffle(nums.begin(), nums.end(), rng);
    llvm::DenseMap<llvm::BasicBlock *, std::uint32_t> numOf;
    for (std::size_t i = 0; i < blocks.size(); ++i) numOf[blocks[i]] = nums[i];

    // State variable, seeded with the first real block's number, in the entry.
    llvm::Instruction *entryTerm = entry.getTerminator();
    llvm::IRBuilder<> eb(entryTerm);
    llvm::AllocaInst *sv = eb.CreateAlloca(i32, nullptr, "jk.sv");
    eb.CreateStore(llvm::ConstantInt::get(i32, numOf[firstReal]), sv);

    // Dispatcher and loop latch.
    llvm::BasicBlock *dispatch =
        llvm::BasicBlock::Create(ctx, "jk.dispatch", &fn, firstReal);
    llvm::BasicBlock *loopEnd = llvm::BasicBlock::Create(ctx, "jk.loopend", &fn);

    entryTerm->eraseFromParent();
    llvm::BranchInst::Create(dispatch, &entry);

    llvm::IRBuilder<> db(dispatch);
    llvm::LoadInst *state = db.CreateLoad(i32, sv, "jk.state");
    llvm::SwitchInst *sw =
        db.CreateSwitch(state, blocks[0], static_cast<unsigned>(blocks.size()));
    for (llvm::BasicBlock *bb : blocks)
        sw->addCase(llvm::ConstantInt::get(i32, numOf[bb]), bb);

    llvm::BranchInst::Create(dispatch, loopEnd);

    // Rewire each block's exit: set the next state and jump to the latch.
    for (llvm::BasicBlock *bb : blocks) {
        auto *br = llvm::dyn_cast<llvm::BranchInst>(bb->getTerminator());
        if (!br) continue;  // ret / unreachable: leave it - it exits the loop

        bool allKnown = true;
        for (llvm::BasicBlock *succ : br->successors())
            allKnown &= numOf.count(succ) != 0;
        if (!allKnown) continue;  // never happens for JOCKY IR; stay safe

        llvm::IRBuilder<> b(br);
        if (br->isUnconditional()) {
            b.CreateStore(llvm::ConstantInt::get(i32, numOf[br->getSuccessor(0)]),
                          sv);
        } else {
            llvm::Value *next = b.CreateSelect(
                br->getCondition(),
                llvm::ConstantInt::get(i32, numOf[br->getSuccessor(0)]),
                llvm::ConstantInt::get(i32, numOf[br->getSuccessor(1)]),
                "jk.next");
            b.CreateStore(next, sv);
        }
        br->eraseFromParent();
        llvm::BranchInst::Create(loopEnd, bb);
    }
    return true;
}

}  // namespace

llvm::PreservedAnalyses FlatteningPass::run(llvm::Module &m,
                                            llvm::ModuleAnalysisManager &) {
    std::mt19937_64 rng(seed_ ^ 0x6a6b0000666c6174ULL /* "jk\0\0flat" */);
    bool changed = false;
    for (llvm::Function &fn : m) {
        if (fn.isDeclaration()) continue;
        changed |= flattenFunction(fn, rng);
    }
    return changed ? llvm::PreservedAnalyses::none()
                   : llvm::PreservedAnalyses::all();
}

llvm::PreservedAnalyses CallIndirectionPass::run(llvm::Module &m,
                                                 llvm::ModuleAnalysisManager &) {
    llvm::LLVMContext &ctx = m.getContext();
    llvm::PointerType *ptrTy = llvm::PointerType::getUnqual(ctx);
    llvm::IntegerType *i64Ty = llvm::Type::getInt64Ty(ctx);

    // Per-module key: the callee address is stored offset by this constant, so
    // the function-pointer globals do not read as plain relocations to `@name`.
    // The offset form (`add (ptrtoint(@f), K)`) is used rather than xor because
    // an object-file relocation is additive - the MC layer rejects xor in a
    // static initializer.
    std::mt19937_64 rng(seed_ ^ 0x6a6b000069646972ULL /* "jk\0\0idir" */);
    llvm::Constant *key = llvm::ConstantInt::get(i64Ty, rng() | 1ULL);

    llvm::DenseMap<llvm::Function *, llvm::GlobalVariable *> slotFor;
    bool changed = false;

    const auto slot = [&](llvm::Function *callee) -> llvm::GlobalVariable * {
        auto it = slotFor.find(callee);
        if (it != slotFor.end()) return it->second;
        // init = ptrtoint(@callee) + key   (both are valid constant exprs and
        // this folds to a single relocation with an addend)
        llvm::Constant *enc = llvm::ConstantExpr::getAdd(
            llvm::ConstantExpr::getPtrToInt(callee, i64Ty), key);
        auto *g = new llvm::GlobalVariable(
            m, i64Ty, /*isConstant=*/false, llvm::GlobalValue::InternalLinkage,
            enc, "jk.fp." + callee->getName());
        g->setUnnamedAddr(llvm::GlobalValue::UnnamedAddr::Global);
        slotFor[callee] = g;
        return g;
    };

    for (llvm::Function &fn : m) {
        if (fn.isDeclaration()) continue;

        for (llvm::BasicBlock &bb : fn) {
            for (llvm::Instruction &inst : llvm::make_early_inc_range(bb)) {
                auto *call = llvm::dyn_cast<llvm::CallInst>(&inst);
                if (!call) continue;

                llvm::Function *callee = call->getCalledFunction();
                if (!callee || callee->isDeclaration() || callee->isIntrinsic())
                    continue;                       // leave printf & friends alone
                if (call->isInlineAsm() || call->isMustTailCall()) continue;

                llvm::IRBuilder<> b(call);
                llvm::Value *enc = b.CreateLoad(i64Ty, slot(callee), "jk.enc");
                llvm::Value *dec = b.CreateSub(enc, key, "jk.dec");
                llvm::Value *fp = b.CreateIntToPtr(dec, ptrTy, "jk.fp");
                call->setCalledOperand(fp);         // type stays; call is now indirect
                changed = true;
            }
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
    if (wanted("split"))
        mpm.addPass(BlockSplittingPass(seed ^ 0x1));
    if (wanted("flatten")) {
        // reg2mem spills phis and cross-block values to stack so flattening
        // cannot break SSA dominance; FlatteningPass requires this.
        mpm.addPass(llvm::createModuleToFunctionPassAdaptor(llvm::RegToMemPass()));
        mpm.addPass(FlatteningPass(seed ^ 0x2));
    }
    if (wanted("indirect"))
        mpm.addPass(CallIndirectionPass(seed ^ 0x3));
    if (wanted("junk"))
        mpm.addPass(JunkInsertionPass(seed ^ 0x4));
}

}  // namespace jocky::codegen
