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

// Integer comparison predicate; signedness picks SLT/ULT etc.
llvm::CmpInst::Predicate intPredicate(ast::BinaryOp op, bool isSigned) {
    switch (op) {
    case ast::BinaryOp::Eq: return llvm::CmpInst::ICMP_EQ;
    case ast::BinaryOp::Ne: return llvm::CmpInst::ICMP_NE;
    case ast::BinaryOp::Lt:
        return isSigned ? llvm::CmpInst::ICMP_SLT : llvm::CmpInst::ICMP_ULT;
    case ast::BinaryOp::Le:
        return isSigned ? llvm::CmpInst::ICMP_SLE : llvm::CmpInst::ICMP_ULE;
    case ast::BinaryOp::Gt:
        return isSigned ? llvm::CmpInst::ICMP_SGT : llvm::CmpInst::ICMP_UGT;
    case ast::BinaryOp::Ge:
        return isSigned ? llvm::CmpInst::ICMP_SGE : llvm::CmpInst::ICMP_UGE;
    default: return llvm::CmpInst::ICMP_EQ;  // not reached
    }
}

// Ordered float comparison predicate (`!=` is unordered, matching C).
llvm::CmpInst::Predicate floatPredicate(ast::BinaryOp op) {
    switch (op) {
    case ast::BinaryOp::Eq: return llvm::CmpInst::FCMP_OEQ;
    case ast::BinaryOp::Ne: return llvm::CmpInst::FCMP_UNE;
    case ast::BinaryOp::Lt: return llvm::CmpInst::FCMP_OLT;
    case ast::BinaryOp::Le: return llvm::CmpInst::FCMP_OLE;
    case ast::BinaryOp::Gt: return llvm::CmpInst::FCMP_OGT;
    case ast::BinaryOp::Ge: return llvm::CmpInst::FCMP_OGE;
    default: return llvm::CmpInst::FCMP_OEQ;  // not reached
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

// The LLVM type for a JOCKY type. `bool` is `i1` (LLVM widens it to a byte in
// memory on its own); the sized integers map to `iN`; `float`/`double` to the
// IEEE types. `void` only appears as a function result.
llvm::Type *CodeGen::llvmType(ast::Type t) {
    switch (t.kind) {
    case ast::TypeKind::Void: return llvm::Type::getVoidTy(ctx_);
    case ast::TypeKind::Bool: return llvm::Type::getInt1Ty(ctx_);
    case ast::TypeKind::Int: return llvm::Type::getIntNTy(ctx_, t.bits);
    case ast::TypeKind::Float:
        return t.bits == 32 ? llvm::Type::getFloatTy(ctx_)
                            : llvm::Type::getDoubleTy(ctx_);
    case ast::TypeKind::Error:
        return i64Ty();  // unreachable post-sema; keeps codegen total
    }
    return i64Ty();
}

llvm::Value *CodeGen::zeroValue(ast::Type t) {
    if (t.isFloat()) return llvm::ConstantFP::get(llvmType(t), 0.0);
    return llvm::ConstantInt::get(llvmType(t), 0);
}

void CodeGen::error(SourceLocation loc, const llvm::Twine &message) {
    diags_.error(loc, message);
}

// top level

std::unique_ptr<llvm::Module> CodeGen::lowerModule(const ast::Module &program) {
    // Pass 1: declare every function so calls resolve no matter the order.
    for (const ast::FunctionDecl *fn : program.functions) declareFunction(*fn);
    declareImplicitMain();

    // Pass 2: lower the bodies.
    for (const ast::FunctionDecl *fn : program.functions) lowerFunctionBody(*fn);
    lowerImplicitMainBody(program);

    return std::move(module_);
}

void CodeGen::declareFunction(const ast::FunctionDecl &fn) {
    // Name clashes (a user `main`, a redefinition) are already rejected by sema.
    llvm::SmallVector<llvm::Type *, 8> paramTypes;
    for (const ast::Param &p : fn.params) paramTypes.push_back(llvmType(p.type));
    auto *fnTy = llvm::FunctionType::get(llvmType(fn.resolvedReturn), paramTypes,
                                         /*isVarArg=*/false);
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

llvm::Constant *CodeGen::internFormat(llvm::StringRef text, llvm::StringRef name) {
    auto it = formats_.find(name);
    if (it != formats_.end()) return it->second;
    llvm::Constant *g =
        builder_.CreateGlobalString(text, name, 0, module_.get());
    formats_[name] = g;
    return g;
}

llvm::Constant *CodeGen::internCString(llvm::StringRef bytes) {
    return builder_.CreateGlobalString(bytes, "jocky.str", 0, module_.get());
}

// func bodies

llvm::AllocaInst *CodeGen::createEntryAlloca(llvm::Function *fn,
                                             llvm::StringRef name,
                                             llvm::Type *type) {
    llvm::IRBuilder<> entryBuilder(&fn->getEntryBlock(),
                                   fn->getEntryBlock().begin());
    return entryBuilder.CreateAlloca(type, nullptr, name);
}

CodeGen::Local *CodeGen::lookupLocal(llvm::StringRef name) {
    auto it = locals_.find(name);
    return it == locals_.end() ? nullptr : &it->second;
}

void CodeGen::emitDefaultReturn() {
    if (currentReturn_.isVoid()) {
        builder_.CreateRetVoid();
        return;
    }
    builder_.CreateRet(zeroValue(currentReturn_));
}

void CodeGen::lowerFunctionBody(const ast::FunctionDecl &fn) {
    llvm::Function *f = functions_.lookup(fn.name);
    if (!f) return;           // its declaration failed earlier
    if (!f->empty()) return;  // already lowered, perchance

    auto *entry = llvm::BasicBlock::Create(ctx_, "entry", f);
    builder_.SetInsertPoint(entry);
    locals_.clear();
    currentReturn_ = fn.resolvedReturn;

    unsigned i = 0;
    for (llvm::Argument &arg : f->args()) {
        const ast::Param &p = fn.params[i];
        arg.setName(p.name);
        llvm::AllocaInst *slot = createEntryAlloca(f, p.name, llvmType(p.type));
        builder_.CreateStore(&arg, slot);
        locals_[p.name] = Local{slot, p.type};
        ++i;
    }

    lowerBlock(*fn.body);

    if (!blockIsTerminated(builder_)) emitDefaultReturn();
}

void CodeGen::lowerImplicitMainBody(const ast::Module &program) {
    auto *entry = llvm::BasicBlock::Create(ctx_, "entry", mainFn_);
    builder_.SetInsertPoint(entry);
    locals_.clear();
    currentReturn_ = ast::Type::intTy();  // main is `-> int` (the exit code)

    for (const ast::Stmt *s : program.topLevelStatements) {
        lowerStmt(*s);
        if (blockIsTerminated(builder_)) break;
    }

    if (!blockIsTerminated(builder_)) builder_.CreateRet(i64(0));
}

void CodeGen::lowerBlock(const ast::Block &block) {
    for (const ast::Stmt *s : block.statements) {
        lowerStmt(*s);
        if (blockIsTerminated(builder_)) break;  // rest is unreachable
    }
}

void CodeGen::lowerStmt(const ast::Stmt &stmt) {
    switch (stmt.kind) {
    case ast::NodeKind::VarDeclStmt: {
        const auto &v = static_cast<const ast::VarDeclStmt &>(stmt);
        llvm::Value *init = lowerExpr(*v.init);
        if (!init) return;
        Local *local = lookupLocal(v.name);
        if (!local) {
            llvm::AllocaInst *slot =
                createEntryAlloca(builder_.GetInsertBlock()->getParent(), v.name,
                                  llvmType(v.declaredType));
            locals_[v.name] = Local{slot, v.declaredType};
            local = lookupLocal(v.name);
        }
        builder_.CreateStore(init, local->slot);
        return;
    }
    case ast::NodeKind::AssignStmt: {
        const auto &a = static_cast<const ast::AssignStmt &>(stmt);
        llvm::Value *value = lowerExpr(*a.value);
        if (!value) return;
        Local *local = lookupLocal(a.name);
        if (!local) {
            error(a.loc,
                  "internal: assignment to a variable sema did not resolve");
            return;
        }
        builder_.CreateStore(value, local->slot);
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
        if (!r.value) {
            emitDefaultReturn();
            return;
        }
        llvm::Value *v = lowerExpr(*r.value);
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

// exprr

llvm::Value *CodeGen::lowerCondition(const ast::Expr &e) {
    llvm::Value *v = lowerExpr(e);
    if (!v) return nullptr;
    if (e.type.isBool()) return v;  // comparisons and bool values are already i1
    // An integer in condition position is `!= 0` (L0.5).
    return builder_.CreateICmpNE(v, llvm::ConstantInt::get(llvmType(e.type), 0),
                                 "tobool");
}

llvm::Value *CodeGen::lowerExpr(const ast::Expr &expr) {
    switch (expr.kind) {
    case ast::NodeKind::IntLiteralExpr: {
        const auto &n = static_cast<const ast::IntLiteralExpr &>(expr);
        return llvm::ConstantInt::get(llvmType(expr.type),
                                      static_cast<std::uint64_t>(n.value),
                                      expr.type.isSigned);
    }
    case ast::NodeKind::FloatLiteralExpr: {
        const auto &n = static_cast<const ast::FloatLiteralExpr &>(expr);
        return llvm::ConstantFP::get(llvmType(expr.type), n.value);
    }
    case ast::NodeKind::CharLiteralExpr:
        return llvm::ConstantInt::get(
            llvmType(expr.type),
            static_cast<const ast::CharLiteralExpr &>(expr).value);
    case ast::NodeKind::BoolLiteralExpr:
        return llvm::ConstantInt::get(
            llvmType(expr.type),
            static_cast<const ast::BoolLiteralExpr &>(expr).value ? 1 : 0);

    case ast::NodeKind::StringLiteralExpr:
        // sema only lets a string literal through as a direct print(...) arg,
        // which lowerPrint handles without calling lowerExpr.
        error(expr.loc, "internal: bare string literal reached codegen");
        return nullptr;

    case ast::NodeKind::VarRefExpr: {
        const auto &v = static_cast<const ast::VarRefExpr &>(expr);
        Local *local = lookupLocal(v.name);
        if (!local) {
            error(v.loc,
                  "internal: reference to a variable sema did not resolve");
            return nullptr;
        }
        return builder_.CreateLoad(llvmType(local->type), local->slot, v.name);
    }

    case ast::NodeKind::UnaryExpr: {
        const auto &u = static_cast<const ast::UnaryExpr &>(expr);
        llvm::Value *operand = lowerExpr(*u.operand);
        if (!operand) return nullptr;
        return expr.type.isFloat() ? builder_.CreateFNeg(operand, "fneg")
                                   : builder_.CreateNeg(operand, "neg");
    }

    case ast::NodeKind::BinaryExpr:
        return lowerBinary(static_cast<const ast::BinaryExpr &>(expr));

    case ast::NodeKind::CallExpr:
        return lowerCall(static_cast<const ast::CallExpr &>(expr));

    case ast::NodeKind::CastExpr:
    case ast::NodeKind::ImplicitConversionExpr:
        return lowerConversion(expr);

    default:
        error(expr.loc, "internal: unexpected expression kind in codegen");
        return nullptr;
    }
}

llvm::Value *CodeGen::lowerConversion(const ast::Expr &expr) {
    const ast::Expr *operand =
        expr.kind == ast::NodeKind::CastExpr
            ? static_cast<const ast::CastExpr &>(expr).operand
            : static_cast<const ast::ImplicitConversionExpr &>(expr).operand;

    llvm::Value *v = lowerExpr(*operand);
    if (!v) return nullptr;
    return emitConvert(v, operand->type, expr.type);
}

llvm::Value *CodeGen::emitConvert(llvm::Value *v, ast::Type from, ast::Type to) {
    if (from == to) return v;
    llvm::Type *dst = llvmType(to);

    if (to.isBool()) {
        if (from.isFloat())
            return builder_.CreateFCmpUNE(
                v, llvm::ConstantFP::get(llvmType(from), 0.0), "tobool");
        return builder_.CreateICmpNE(
            v, llvm::ConstantInt::get(llvmType(from), 0), "tobool");
    }
    if (from.isBool()) {
        if (to.isFloat())
            return builder_.CreateUIToFP(v, dst, "booltofp");
        return builder_.CreateZExt(v, dst, "booltoint");
    }
    if (from.isInteger() && to.isInteger()) {
        if (to.bits == from.bits) return v;  // sign reinterpretation is a no-op
        if (to.bits < from.bits) return builder_.CreateTrunc(v, dst, "trunc");
        return from.isSigned ? builder_.CreateSExt(v, dst, "sext")
                             : builder_.CreateZExt(v, dst, "zext");
    }
    if (from.isInteger() && to.isFloat())
        return from.isSigned ? builder_.CreateSIToFP(v, dst, "sitofp")
                             : builder_.CreateUIToFP(v, dst, "uitofp");
    if (from.isFloat() && to.isInteger())
        return to.isSigned ? builder_.CreateFPToSI(v, dst, "fptosi")
                           : builder_.CreateFPToUI(v, dst, "fptoui");
    if (from.isFloat() && to.isFloat())
        return to.bits < from.bits ? builder_.CreateFPTrunc(v, dst, "fptrunc")
                                   : builder_.CreateFPExt(v, dst, "fpext");
    return v;  // unreachable post-sema
}

llvm::Value *CodeGen::lowerBinary(const ast::BinaryExpr &e) {
    llvm::Value *l = lowerExpr(*e.lhs);
    llvm::Value *r = lowerExpr(*e.rhs);
    if (!l || !r) return nullptr;

    // sema has coerced both sides to one type; read it off the lhs.
    const ast::Type opTy = e.lhs->type;

    if (ast::isComparison(e.op)) {
        return opTy.isFloat()
                   ? builder_.CreateFCmp(floatPredicate(e.op), l, r, "fcmp")
                   : builder_.CreateICmp(intPredicate(e.op, opTy.isSigned), l, r,
                                         "cmp");
    }

    if (opTy.isFloat()) {
        switch (e.op) {
        case ast::BinaryOp::Add: return builder_.CreateFAdd(l, r, "fadd");
        case ast::BinaryOp::Sub: return builder_.CreateFSub(l, r, "fsub");
        case ast::BinaryOp::Mul: return builder_.CreateFMul(l, r, "fmul");
        case ast::BinaryOp::Div: return builder_.CreateFDiv(l, r, "fdiv");
        default: break;
        }
        error(e.loc, "internal: bad float binary operator in codegen");
        return nullptr;
    }

    switch (e.op) {
    case ast::BinaryOp::Add: return builder_.CreateAdd(l, r, "add");
    case ast::BinaryOp::Sub: return builder_.CreateSub(l, r, "sub");
    case ast::BinaryOp::Mul: return builder_.CreateMul(l, r, "mul");
    case ast::BinaryOp::Div:
        return opTy.isSigned ? builder_.CreateSDiv(l, r, "div")
                             : builder_.CreateUDiv(l, r, "div");
    case ast::BinaryOp::Mod:
        return opTy.isSigned ? builder_.CreateSRem(l, r, "rem")
                             : builder_.CreateURem(l, r, "rem");
    default: break;
    }
    error(e.loc, "internal: bad integer binary operator in codegen");
    return nullptr;
}

llvm::Value *CodeGen::lowerCall(const ast::CallExpr &e) {
    if (e.callee == "print") {
        if (e.args.size() != 1) {
            error(e.loc,
                  "internal: print reached codegen with a bad argument count");
            return nullptr;
        }
        return lowerPrint(*e.args[0]);
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
    llvm::CallInst *call = builder_.CreateCall(callee, args);
    if (!callee->getReturnType()->isVoidTy()) call->setName("call");
    return call;
}

// `print(x)`: the format string is chosen from the argument's type (L0.8).
llvm::Value *CodeGen::lowerPrint(const ast::Expr &arg) {
    llvm::Function *printf = getOrDeclarePrintf();

    auto call = [&](llvm::Constant *fmt, llvm::Value *value) {
        llvm::Value *a[] = {fmt, value};
        builder_.CreateCall(printf->getFunctionType(), printf, a);
    };

    if (arg.kind == ast::NodeKind::StringLiteralExpr) {
        const auto &s = static_cast<const ast::StringLiteralExpr &>(arg);
        call(internFormat("%s\n", "jocky.fmt.str"), internCString(s.value));
        return i64(0);
    }

    llvm::Value *v = lowerExpr(arg);
    if (!v) return nullptr;
    const ast::Type t = arg.type;

    if (t.isBool()) {
        llvm::Value *sel = builder_.CreateSelect(v, internCString("true"),
                                                 internCString("false"),
                                                 "boolstr");
        call(internFormat("%s\n", "jocky.fmt.str"), sel);
    } else if (t.isFloat()) {
        llvm::Value *d =
            t.bits == 32
                ? builder_.CreateFPExt(v, llvm::Type::getDoubleTy(ctx_), "fpext")
                : v;
        call(internFormat("%g\n", "jocky.fmt.flt"), d);
    } else if (t == ast::Type::charTy()) {
        llvm::Value *c =
            builder_.CreateZExt(v, llvm::Type::getInt32Ty(ctx_), "chararg");
        call(internFormat("%c\n", "jocky.fmt.chr"), c);
    } else {  // any other integer
        llvm::Value *wide = v;
        if (t.bits < 64)
            wide = t.isSigned ? builder_.CreateSExt(v, i64Ty(), "intarg")
                              : builder_.CreateZExt(v, i64Ty(), "intarg");
        if (t.isSigned)
            call(internFormat("%lld\n", "jocky.fmt.int"), wide);
        else
            call(internFormat("%llu\n", "jocky.fmt.uint"), wide);
    }
    return i64(0);  // print(...) evaluates to 0
}

}  // namespace jocky::codegen
