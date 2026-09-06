// Lowering: an AST in, an llvm::Module out.
//
// Strategy is deliberately plain: every JOCKY value is a 64-bit integer
// (LLVM i64), and every local variable is a stack slot (an alloca) that we
// load from and store to. We do not build SSA by hand - `-O1` (mem2reg) does
// that later if asked; `-O0` just leaves the loads and stores in place, which
// is still correct.
//
// By the time codegen runs, the semantic-analysis stage (src/sema/) has
// already resolved every name and checked every call. Codegen trusts that: the
// `error(...)` calls left here are marked "internal:" and only fire on a
// compiler bug, not on bad user input.

#ifndef JOCKY_CODEGEN_CODEGEN_H
#define JOCKY_CODEGEN_CODEGEN_H

#include "jocky/ast/AST.h"

#include <memory>

#include <llvm/ADT/StringMap.h>
#include <llvm/ADT/StringRef.h>
#include <llvm/IR/IRBuilder.h>

namespace llvm {
class AllocaInst;
class BasicBlock;
class Constant;
class Function;
class LLVMContext;
class Module;
class Value;
}  // namespace llvm

namespace jocky {

class DiagnosticEngine;

namespace codegen {

class CodeGen {
public:
    CodeGen(llvm::LLVMContext &context, llvm::StringRef moduleName,
            DiagnosticEngine &diags);

    // Lowers the whole program. Always returns a module; the caller must check
    // diags.hasErrors() and discard the result if anything was reported.
    std::unique_ptr<llvm::Module> lowerModule(const ast::Module &program);

    // A local variable: its stack slot plus the JOCKY type stored in it.
    struct Local {
        llvm::AllocaInst *slot = nullptr;
        ast::Type type;
    };

private:
    // --- helpers for common types / constants ---
    llvm::IntegerType *i64Ty();
    llvm::PointerType *ptrTy();  // opaque pointer
    llvm::ConstantInt *i64(std::int64_t v);
    llvm::Type *llvmType(ast::Type t);
    llvm::StructType *sliceTy();  // the { ptr, i64 } layout every slice shares
    llvm::Value *zeroValue(ast::Type t);

    // --- declarations ---
    void declareFunction(const ast::FunctionDecl &fn);
    void declareImplicitMain();
    llvm::Function *getOrDeclarePrintf();
    llvm::Constant *internFormat(llvm::StringRef text, llvm::StringRef name);
    llvm::Constant *internCString(llvm::StringRef bytes);

    // --- lowering ---
    void lowerFunctionBody(const ast::FunctionDecl &fn);
    void lowerImplicitMainBody(const ast::Module &program);
    void lowerBlock(const ast::Block &block);
    void lowerStmt(const ast::Stmt &stmt);
    void lowerIf(const ast::IfStmt &stmt);
    void lowerWhile(const ast::WhileStmt &stmt);
    void emitDefaultReturn();  // the `ret` for a fell-through function body

    llvm::Value *lowerExpr(const ast::Expr &expr);  // value has type expr.type
    llvm::Value *lowerBinary(const ast::BinaryExpr &e);
    llvm::Value *lowerCall(const ast::CallExpr &e);
    llvm::Value *lowerPrint(const ast::Expr &arg);
    llvm::Value *lowerConversion(const ast::Expr &expr);  // Cast / ImplicitConversion
    llvm::Value *emitConvert(llvm::Value *v, ast::Type from, ast::Type to);
    llvm::Value *lowerCondition(const ast::Expr &e);  // -> i1 (or null on error)

    // Arrays and slices (L0.6).
    llvm::Value *lowerAddr(const ast::Expr &e);  // address of an lvalue
    llvm::Value *lowerIndex(const ast::IndexExpr &e);
    llvm::Value *lowerSliceExpr(const ast::SliceExpr &e);
    llvm::Value *lowerMember(const ast::MemberExpr &e);
    llvm::Value *lowerArrayLiteral(const ast::ArrayLiteralExpr &e);
    llvm::Value *lowerArrayToSlice(const ast::ArrayToSliceExpr &e);
    llvm::Value *makeSlice(llvm::Value *basePtr, llvm::Value *len);
    // The base pointer and element count of an array or slice expression.
    struct SeqRef {
        llvm::Value *basePtr = nullptr;  // ptr to the first element
        llvm::Value *len = nullptr;      // i64 element count
        ast::Type elem;
    };
    SeqRef sequenceOf(const ast::Expr &e);

    llvm::AllocaInst *createEntryAlloca(llvm::Function *fn, llvm::StringRef name,
                                        llvm::Type *type);
    Local *lookupLocal(llvm::StringRef name);

    // Reports a user error. Lowering then continues where it safely can (via
    // null Values propagating up); the driver discards the module afterwards
    // because diags.hasErrors() is set.
    void error(SourceLocation loc, const llvm::Twine &message);

    llvm::LLVMContext &ctx_;
    DiagnosticEngine &diags_;
    std::unique_ptr<llvm::Module> module_;
    llvm::IRBuilder<> builder_;

    llvm::StringMap<llvm::Function *> functions_;
    llvm::StringMap<Local> locals_;  // reset per function
    ast::Type currentReturn_;        // return type of the function being lowered

    llvm::Function *mainFn_ = nullptr;  // the implicit main
    llvm::Function *printfFn_ = nullptr;
    llvm::StructType *sliceTy_ = nullptr;
    llvm::StringMap<llvm::Constant *> formats_;  // printf format strings, by name
};

}  // namespace codegen
}  // namespace jocky

#endif  // JOCKY_CODEGEN_CODEGEN_H
