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
    case ast::TypeKind::Array:
        return llvm::ArrayType::get(llvmType(t.elem()), t.length);
    case ast::TypeKind::Slice:
        return sliceTy();
    case ast::TypeKind::Error:
        return i64Ty();  // unreachable post-sema; keeps codegen total
    }
    return i64Ty();
}

// Every slice, whatever its element type, is a { ptr, i64 } pair: the base
// address and the element count. The element type is only tracked in ast::Type.
llvm::StructType *CodeGen::sliceTy() {
    if (!sliceTy_)
        sliceTy_ = llvm::StructType::create({ptrTy(), i64Ty()}, "jocky.slice");
    return sliceTy_;
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
        Local *local = lookupLocal(v.name);
        if (!local) {
            llvm::AllocaInst *slot =
                createEntryAlloca(builder_.GetInsertBlock()->getParent(), v.name,
                                  llvmType(v.declaredType));
            locals_[v.name] = Local{slot, v.declaredType};
            local = lookupLocal(v.name);
        }
        if (!v.init) return;  // `var buf: char[N];` - storage left unset
        llvm::Value *init = lowerExpr(*v.init);
        if (!init) return;
        builder_.CreateStore(init, local->slot);
        return;
    }
    case ast::NodeKind::AssignStmt: {
        const auto &a = static_cast<const ast::AssignStmt &>(stmt);
        llvm::Value *value = lowerExpr(*a.value);
        if (!value) return;
        llvm::Value *addr = lowerAddr(*a.target);
        if (!addr) return;
        builder_.CreateStore(value, addr);
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

    case ast::NodeKind::StringLiteralExpr: {
        // A string literal is a `char[len + 1]`. As a value, load it from its
        // interned global (usually it decays to a slice first, see below).
        const auto &s = static_cast<const ast::StringLiteralExpr &>(expr);
        return builder_.CreateLoad(llvmType(expr.type), internCString(s.value),
                                   "str");
    }

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

    case ast::NodeKind::ArrayLiteralExpr:
        return lowerArrayLiteral(static_cast<const ast::ArrayLiteralExpr &>(expr));
    case ast::NodeKind::IndexExpr:
        return lowerIndex(static_cast<const ast::IndexExpr &>(expr));
    case ast::NodeKind::SliceExpr:
        return lowerSliceExpr(static_cast<const ast::SliceExpr &>(expr));
    case ast::NodeKind::MemberExpr:
        return lowerMember(static_cast<const ast::MemberExpr &>(expr));
    case ast::NodeKind::ArrayToSliceExpr:
        return lowerArrayToSlice(
            static_cast<const ast::ArrayToSliceExpr &>(expr));

    default:
        error(expr.loc, "internal: unexpected expression kind in codegen");
        return nullptr;
    }
}

// The address of an lvalue: a variable's slot, or a computed element address.
llvm::Value *CodeGen::lowerAddr(const ast::Expr &e) {
    if (e.kind == ast::NodeKind::VarRefExpr) {
        Local *local = lookupLocal(static_cast<const ast::VarRefExpr &>(e).name);
        if (!local) {
            error(e.loc, "internal: lvalue names a variable sema did not "
                         "resolve");
            return nullptr;
        }
        return local->slot;
    }
    if (e.kind == ast::NodeKind::IndexExpr) {
        const auto &ix = static_cast<const ast::IndexExpr &>(e);
        SeqRef seq = sequenceOf(*ix.base);
        if (!seq.basePtr) return nullptr;
        llvm::Value *idx = lowerExpr(*ix.index);
        if (!idx) return nullptr;
        return builder_.CreateGEP(llvmType(seq.elem), seq.basePtr, idx,
                                  "elt.addr");
    }
    error(e.loc, "internal: expression is not an lvalue in codegen");
    return nullptr;
}

// The base pointer + length of an array or slice expression, for indexing and
// slicing. Arrays are addressed in place; slices are unpacked.
CodeGen::SeqRef CodeGen::sequenceOf(const ast::Expr &e) {
    SeqRef r;
    if (e.type.isArray()) {
        r.elem = e.type.elem();
        r.len = i64(static_cast<std::int64_t>(e.type.length));
        if (e.kind == ast::NodeKind::StringLiteralExpr) {
            r.basePtr = internCString(
                static_cast<const ast::StringLiteralExpr &>(e).value);
        } else {
            llvm::Value *arrPtr = lowerAddr(e);
            if (!arrPtr) return {};
            r.basePtr = builder_.CreateGEP(
                llvmType(e.type), arrPtr,
                {i64(0), i64(0)}, "arr.base");
        }
        return r;
    }
    if (e.type.isSlice()) {
        r.elem = e.type.elem();
        llvm::Value *s = lowerExpr(e);
        if (!s) return {};
        r.basePtr = builder_.CreateExtractValue(s, 0, "slc.ptr");
        r.len = builder_.CreateExtractValue(s, 1, "slc.len");
        return r;
    }
    error(e.loc, "internal: sequenceOf on a non-array/slice type");
    return {};
}

llvm::Value *CodeGen::makeSlice(llvm::Value *basePtr, llvm::Value *len) {
    llvm::Value *s = llvm::UndefValue::get(sliceTy());
    s = builder_.CreateInsertValue(s, basePtr, 0, "slc.set.ptr");
    s = builder_.CreateInsertValue(s, len, 1, "slc.set.len");
    return s;
}

llvm::Value *CodeGen::lowerIndex(const ast::IndexExpr &e) {
    llvm::Value *addr = lowerAddr(e);
    if (!addr) return nullptr;
    return builder_.CreateLoad(llvmType(e.type), addr, "elt");
}

llvm::Value *CodeGen::lowerMember(const ast::MemberExpr &e) {
    // Only `.len` exists.
    if (e.base->type.isArray())
        return i64(static_cast<std::int64_t>(e.base->type.length));
    llvm::Value *s = lowerExpr(*e.base);
    if (!s) return nullptr;
    return builder_.CreateExtractValue(s, 1, "len");
}

llvm::Value *CodeGen::lowerSliceExpr(const ast::SliceExpr &e) {
    SeqRef seq = sequenceOf(*e.base);
    if (!seq.basePtr) return nullptr;

    llvm::Value *lo = e.lo ? lowerExpr(*e.lo) : i64(0);
    if (!lo) return nullptr;
    llvm::Value *hi = e.hi ? lowerExpr(*e.hi) : seq.len;
    if (!hi) return nullptr;

    llvm::Value *base =
        builder_.CreateGEP(llvmType(seq.elem), seq.basePtr, lo, "sub.base");
    llvm::Value *len = builder_.CreateSub(hi, lo, "sub.len");
    return makeSlice(base, len);
}

llvm::Value *CodeGen::lowerArrayToSlice(const ast::ArrayToSliceExpr &e) {
    SeqRef seq = sequenceOf(*e.array);
    if (!seq.basePtr) return nullptr;
    return makeSlice(seq.basePtr, seq.len);
}

llvm::Value *CodeGen::lowerArrayLiteral(const ast::ArrayLiteralExpr &e) {
    llvm::Type *arrTy = llvmType(e.type);
    llvm::Value *tmp = createEntryAlloca(
        builder_.GetInsertBlock()->getParent(), "arr.lit", arrTy);
    for (std::size_t i = 0; i < e.elements.size(); ++i) {
        llvm::Value *el = lowerExpr(*e.elements[i]);
        if (!el) return nullptr;
        llvm::Value *slot = builder_.CreateGEP(
            arrTy, tmp,
            {i64(0), i64(static_cast<std::int64_t>(i))}, "arr.lit.elt");
        builder_.CreateStore(el, slot);
    }
    return builder_.CreateLoad(arrTy, tmp, "arr.lit.val");
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

    const ast::Type t = arg.type;

    if (arg.kind == ast::NodeKind::StringLiteralExpr) {
        const auto &s = static_cast<const ast::StringLiteralExpr &>(arg);
        call(internFormat("%s\n", "jocky.fmt.str"), internCString(s.value));
        return i64(0);
    }

    // A `char[N]` is treated as a C string (NUL-terminated). A `char[]` slice
    // may be a sub-view with no terminator, so print exactly `len` bytes.
    if (t.isArray()) {
        SeqRef seq = sequenceOf(arg);
        if (!seq.basePtr) return nullptr;
        call(internFormat("%s\n", "jocky.fmt.str"), seq.basePtr);
        return i64(0);
    }
    if (t.isSlice()) {
        SeqRef seq = sequenceOf(arg);
        if (!seq.basePtr) return nullptr;
        llvm::Value *n =
            builder_.CreateTrunc(seq.len, llvm::Type::getInt32Ty(ctx_), "slen");
        llvm::Value *a[] = {internFormat("%.*s\n", "jocky.fmt.pstr"), n,
                            seq.basePtr};
        builder_.CreateCall(printf->getFunctionType(), printf, a);
        return i64(0);
    }

    llvm::Value *v = lowerExpr(arg);
    if (!v) return nullptr;

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
