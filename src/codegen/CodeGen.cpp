#include "jocky/codegen/CodeGen.h"

#include "jocky/Support/Diagnostic.h"

#include <llvm/ADT/SmallVector.h>
#include <llvm/ADT/Twine.h>
#include <llvm/IR/BasicBlock.h>
#include <llvm/IR/Constants.h>
#include <llvm/IR/DerivedTypes.h>
#include <llvm/IR/Function.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/Module.h>
#include <llvm/IR/Type.h>

namespace jocky::codegen {

namespace {

llvm::CmpInst::Predicate predicateFor(ast::BinaryOp op) {
    switch (op) {
    case ast::BinaryOp::Eq: return llvm::CmpInst::ICMP_EQ;
    case ast::BinaryOp::Ne: return llvm::CmpInst::ICMP_NE;
    case ast::BinaryOp::Lt: return llvm::CmpInst::ICMP_SLT;
    case ast::BinaryOp::Le: return llvm::CmpInst::ICMP_SLE;
    case ast::BinaryOp::Gt: return llvm::CmpInst::ICMP_SGT;
    case ast::BinaryOp::Ge: return llvm::CmpInst::ICMP_SGE;
    default: return llvm::CmpInst::ICMP_EQ;  // not reached for non-comparisons
    }
}

bool isComparison(ast::BinaryOp op) {
    switch (op) {
    case ast::BinaryOp::Eq:
    case ast::BinaryOp::Ne:
    case ast::BinaryOp::Lt:
    case ast::BinaryOp::Le:
    case ast::BinaryOp::Gt:
    case ast::BinaryOp::Ge:
        return true;
    default:
        return false;
    }
}

bool blockIsTerminated(const llvm::IRBuilder<> &b) {
    return b.GetInsertBlock()->getTerminator() != nullptr;
}

}  // namespace

CodeGen::CodeGen(llvm::LLVMContext &context, llvm::StringRef moduleName,
                 DiagnosticEngine &diags)
    : ctx_(context),
      diags_(diags),
      module_(std::make_unique<llvm::Module>(moduleName, context)),
      builder_(context) {}

llvm::IntegerType *CodeGen::i64Ty() { return llvm::Type::getInt64Ty(ctx_); }

llvm::PointerType *CodeGen::ptrTy() { return llvm::PointerType::getUnqual(ctx_); }

llvm::ConstantInt *CodeGen::i64(std::int64_t v) {
    return llvm::ConstantInt::getSigned(i64Ty(), v);
}

void CodeGen::error(SourceLocation loc, const llvm::Twine &message) {
    diags_.error(loc, message);
}

// --- top level ------------------------------------------------------

std::unique_ptr<llvm::Module> CodeGen::lowerModule(const ast::Module &program) {
    // Pass 1: declare every function so calls resolve no matter the order.
    for (const ast::FunctionDecl *fn : program.functions) declareFunction(*fn);
    declareImplicitMain();

    // Pass 2: lower the bodies. This runs even if pass 1 reported errors so
    // that independent problems are all found in one go; the module is thrown
    // away by the caller when diags.hasErrors().
    for (const ast::FunctionDecl *fn : program.functions) lowerFunctionBody(*fn);
    lowerImplicitMainBody(program);

    return std::move(module_);
}

void CodeGen::declareFunction(const ast::FunctionDecl &fn) {
    // Name clashes (a user `main`, a redefinition) are already rejected by sema;
    // codegen only ever sees a well-formed module.
    llvm::SmallVector<llvm::Type *, 8> paramTypes(fn.params.size(), i64Ty());
    auto *fnTy = llvm::FunctionType::get(i64Ty(), paramTypes, /*isVarArg=*/false);
    auto *f = llvm::Function::Create(fnTy, llvm::Function::ExternalLinkage,
                                     fn.name, module_.get());
    functions_[fn.name] = f;
}

void CodeGen::declareImplicitMain() {
    auto *fnTy = llvm::FunctionType::get(i64Ty(), /*isVarArg=*/false);
    mainFn_ = llvm::Function::Create(fnTy, llvm::Function::ExternalLinkage, "main",
                                     module_.get());
}

llvm::Function *CodeGen::getOrDeclarePrintf() {
    if (printfFn_) return printfFn_;
    auto *fnTy = llvm::FunctionType::get(llvm::Type::getInt32Ty(ctx_), {ptrTy()},
                                         /*isVarArg=*/true);
    printfFn_ = llvm::Function::Create(fnTy, llvm::Function::ExternalLinkage,
                                       "printf", module_.get());
    return printfFn_;
}

llvm::Constant *CodeGen::internFormat(bool forString) {
    if (forString) {
        if (!strFormat_)
            strFormat_ = builder_.CreateGlobalString("%s\n", "jocky.fmt.str", 0,
                                                     module_.get());
        return strFormat_;
    }
    if (!intFormat_)
        intFormat_ = builder_.CreateGlobalString("%lld\n", "jocky.fmt.int", 0,
                                                 module_.get());
    return intFormat_;
}

llvm::Constant *CodeGen::internCString(llvm::StringRef bytes) {
    return builder_.CreateGlobalString(bytes, "jocky.str", 0, module_.get());
}

// --- function bodies --------------------------------------------

llvm::AllocaInst *CodeGen::createEntryAlloca(llvm::Function *fn,
                                             llvm::StringRef name) {
    llvm::IRBuilder<> entryBuilder(&fn->getEntryBlock(),
                                   fn->getEntryBlock().begin());
    return entryBuilder.CreateAlloca(i64Ty(), nullptr, name);
}

llvm::AllocaInst *CodeGen::lookupLocal(llvm::StringRef name) {
    auto it = locals_.find(name);
    return it == locals_.end() ? nullptr : it->second;
}

void CodeGen::lowerFunctionBody(const ast::FunctionDecl &fn) {
    llvm::Function *f = functions_.lookup(fn.name);
    if (!f) return;         // its declaration failed earlier
    if (!f->empty()) return;  // already lowered (e.g. a duplicate declaration)

    auto *entry = llvm::BasicBlock::Create(ctx_, "entry", f);
    builder_.SetInsertPoint(entry);
    locals_.clear();

    unsigned i = 0;
    for (llvm::Argument &arg : f->args()) {
        const std::string &paramName = fn.params[i].name;
        arg.setName(paramName);
        llvm::AllocaInst *slot = createEntryAlloca(f, paramName);
        builder_.CreateStore(&arg, slot);
        locals_[paramName] = slot;
        ++i;
    }

    lowerBlock(*fn.body);

    if (!blockIsTerminated(builder_)) builder_.CreateRet(i64(0));
}

void CodeGen::lowerImplicitMainBody(const ast::Module &program) {
    auto *entry = llvm::BasicBlock::Create(ctx_, "entry", mainFn_);
    builder_.SetInsertPoint(entry);
    locals_.clear();

    for (const ast::Stmt *s : program.topLevelStatements) {
        lowerStmt(*s);
        if (blockIsTerminated(builder_)) break;
    }

    if (!blockIsTerminated(builder_)) builder_.CreateRet(i64(0));
}

void CodeGen::lowerBlock(const ast::Block &block) {
    for (const ast::Stmt *s : block.statements) {
        lowerStmt(*s);
        if (blockIsTerminated(builder_)) break;  // rest of the block is unreachable
    }
}

void CodeGen::lowerStmt(const ast::Stmt &stmt) {
    switch (stmt.kind) {
    case ast::NodeKind::VarDeclStmt: {
        const auto &v = static_cast<const ast::VarDeclStmt &>(stmt);
        llvm::Value *init = lowerExpr(*v.init);
        if (!init) return;
        llvm::AllocaInst *slot = lookupLocal(v.name);
        if (!slot) {
            slot = createEntryAlloca(builder_.GetInsertBlock()->getParent(),
                                     v.name);
            locals_[v.name] = slot;
        }
        builder_.CreateStore(init, slot);
        return;
    }
    case ast::NodeKind::AssignStmt: {
        const auto &a = static_cast<const ast::AssignStmt &>(stmt);
        llvm::Value *value = lowerExpr(*a.value);
        if (!value) return;
        llvm::AllocaInst *slot = lookupLocal(a.name);
        if (!slot) {
            error(a.loc, "internal: assignment to a variable sema did not resolve");
            return;
        }
        builder_.CreateStore(value, slot);
        return;
    }
    case ast::NodeKind::ExprStmt:
        lowerExpr(*static_cast<const ast::ExprStmt &>(stmt).expr);
        return;
    case ast::NodeKind::IfStmt:
        lowerIf(static_cast<const ast::IfStmt &>(stmt));
        return;
    case ast::NodeKind::WhileStmt:
        lowerWhile(static_cast<const ast::WhileStmt &>(stmt));
        return;
    case ast::NodeKind::ReturnStmt: {
        const auto &r = static_cast<const ast::ReturnStmt &>(stmt);
        llvm::Value *v = r.value ? lowerExpr(*r.value) : i64(0);
        if (!v) return;
        builder_.CreateRet(v);
        return;
    }
    case ast::NodeKind::Block:
        lowerBlock(static_cast<const ast::Block &>(stmt));
        return;
    default:
        error(stmt.loc, "internal: unexpected statement kind in codegen");
        return;
    }
}

void CodeGen::lowerIf(const ast::IfStmt &stmt) {
    llvm::Value *cond = lowerCondition(*stmt.condition);
    if (!cond) return;

    llvm::Function *fn = builder_.GetInsertBlock()->getParent();
    auto *thenBB = llvm::BasicBlock::Create(ctx_, "if.then", fn);
    auto *elseBB =
        stmt.elseBlock ? llvm::BasicBlock::Create(ctx_, "if.else", fn) : nullptr;
    auto *contBB = llvm::BasicBlock::Create(ctx_, "if.cont", fn);

    builder_.CreateCondBr(cond, thenBB, elseBB ? elseBB : contBB);

    builder_.SetInsertPoint(thenBB);
    lowerBlock(*stmt.thenBlock);
    if (!blockIsTerminated(builder_)) builder_.CreateBr(contBB);

    if (elseBB) {
        builder_.SetInsertPoint(elseBB);
        lowerBlock(*stmt.elseBlock);
        if (!blockIsTerminated(builder_)) builder_.CreateBr(contBB);
    }

    builder_.SetInsertPoint(contBB);
}

void CodeGen::lowerWhile(const ast::WhileStmt &stmt) {
    llvm::Function *fn = builder_.GetInsertBlock()->getParent();
    auto *condBB = llvm::BasicBlock::Create(ctx_, "while.cond", fn);
    auto *bodyBB = llvm::BasicBlock::Create(ctx_, "while.body", fn);
    auto *endBB = llvm::BasicBlock::Create(ctx_, "while.end", fn);

    builder_.CreateBr(condBB);

    builder_.SetInsertPoint(condBB);
    llvm::Value *cond = lowerCondition(*stmt.condition);
    if (!cond) return;
    builder_.CreateCondBr(cond, bodyBB, endBB);

    builder_.SetInsertPoint(bodyBB);
    lowerBlock(*stmt.body);
    if (!blockIsTerminated(builder_)) builder_.CreateBr(condBB);

    builder_.SetInsertPoint(endBB);
}

// --- expressions ----------------------------------------------

llvm::Value *CodeGen::lowerCondition(const ast::Expr &e) {
    // A comparison is lowered straight to an i1 so the branch reads it directly.
    if (e.kind == ast::NodeKind::BinaryExpr) {
        const auto &b = static_cast<const ast::BinaryExpr &>(e);
        if (isComparison(b.op)) {
            llvm::Value *l = lowerExpr(*b.lhs);
            llvm::Value *r = lowerExpr(*b.rhs);
            if (!l || !r) return nullptr;
            return builder_.CreateICmp(predicateFor(b.op), l, r, "cmp");
        }
    }
    // Anything else: treat non-zero as true.
    llvm::Value *v = lowerExpr(e);
    if (!v) return nullptr;
    return builder_.CreateICmpNE(v, i64(0), "tobool");
}

llvm::Value *CodeGen::lowerExpr(const ast::Expr &expr) {
    switch (expr.kind) {
    case ast::NodeKind::IntLiteralExpr:
        return i64(static_cast<const ast::IntLiteralExpr &>(expr).value);

    case ast::NodeKind::StringLiteralExpr:
        // sema only lets a string literal through as a direct print(...) argument,
        // which lowerCall handles without calling lowerExpr.
        error(expr.loc, "internal: bare string literal reached codegen");
        return nullptr;

    case ast::NodeKind::VarRefExpr: {
        const auto &v = static_cast<const ast::VarRefExpr &>(expr);
        llvm::AllocaInst *slot = lookupLocal(v.name);
        if (!slot) {
            error(v.loc, "internal: reference to a variable sema did not resolve");
            return nullptr;
        }
        return builder_.CreateLoad(i64Ty(), slot, v.name);
    }

    case ast::NodeKind::UnaryExpr: {
        const auto &u = static_cast<const ast::UnaryExpr &>(expr);
        llvm::Value *operand = lowerExpr(*u.operand);
        if (!operand) return nullptr;
        return builder_.CreateNeg(operand, "neg");  // only Neg exists in v0
    }

    case ast::NodeKind::BinaryExpr:
        return lowerBinary(static_cast<const ast::BinaryExpr &>(expr));

    case ast::NodeKind::CallExpr:
        return lowerCall(static_cast<const ast::CallExpr &>(expr));

    default:
        error(expr.loc, "internal: unexpected expression kind in codegen");
        return nullptr;
    }
}

llvm::Value *CodeGen::lowerBinary(const ast::BinaryExpr &e) {
    llvm::Value *l = lowerExpr(*e.lhs);
    llvm::Value *r = lowerExpr(*e.rhs);
    if (!l || !r) return nullptr;

    switch (e.op) {
    case ast::BinaryOp::Add: return builder_.CreateAdd(l, r, "add");
    case ast::BinaryOp::Sub: return builder_.CreateSub(l, r, "sub");
    case ast::BinaryOp::Mul: return builder_.CreateMul(l, r, "mul");
    case ast::BinaryOp::Div: return builder_.CreateSDiv(l, r, "div");
    case ast::BinaryOp::Mod: return builder_.CreateSRem(l, r, "rem");
    default:
        break;  // a comparison; handled below
    }

    // Comparison used as a value: i1 result widened back to i64 (0 or 1).
    llvm::Value *cmp = builder_.CreateICmp(predicateFor(e.op), l, r, "cmp");
    return builder_.CreateZExt(cmp, i64Ty(), "ext");
}

llvm::Value *CodeGen::lowerCall(const ast::CallExpr &e) {
    if (e.callee == "print") {
        if (e.args.size() != 1) {
            error(e.loc, "internal: print reached codegen with a bad argument count");
            return nullptr;
        }
        const ast::Expr &arg = *e.args[0];
        llvm::Function *printf = getOrDeclarePrintf();

        if (arg.kind == ast::NodeKind::StringLiteralExpr) {
            const auto &s = static_cast<const ast::StringLiteralExpr &>(arg);
            llvm::Value *callArgs[] = {internFormat(/*forString=*/true),
                                       internCString(s.value)};
            builder_.CreateCall(printf->getFunctionType(), printf, callArgs);
        } else {
            llvm::Value *v = lowerExpr(arg);
            if (!v) return nullptr;
            llvm::Value *callArgs[] = {internFormat(/*forString=*/false), v};
            builder_.CreateCall(printf->getFunctionType(), printf, callArgs);
        }
        return i64(0);  // print(...) has the value 0
    }

    llvm::Function *callee = functions_.lookup(e.callee);
    if (!callee) {
        error(e.loc, "internal: call to a function sema did not resolve");
        return nullptr;
    }

    llvm::SmallVector<llvm::Value *, 8> args;
    for (const ast::Expr *a : e.args) {
        llvm::Value *v = lowerExpr(*a);
        if (!v) return nullptr;
        args.push_back(v);
    }
    return builder_.CreateCall(callee, args, "call");
}

}  // namespace jocky::codegen
