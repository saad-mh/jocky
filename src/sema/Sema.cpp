// Semantic analysis. See jocky/sema/Sema.h.
//
// This is a two-pass walk of the module:
//   1. register every function's name and parameter count, so calls resolve
//      regardless of source order;
//   2. walk each function body (and the implicit main's top-level statements)
//      in source order, resolving names and checking calls.
//
// The scope model matches JOCKY v0 exactly: there are no nested scopes. A `var`
// becomes visible for the rest of its function the moment its initializer has
// been checked, and never goes out of scope before the function ends. The walk
// is in source order, so a name used before its declaration is "undeclared".

#include "jocky/sema/Sema.h"

#include "jocky/Support/Diagnostic.h"
#include "jocky/ast/AST.h"

#include <llvm/ADT/StringMap.h>
#include <llvm/ADT/StringSet.h>
#include <llvm/ADT/Twine.h>

#include <cstddef>

namespace jocky::sema {

namespace {

// A ceiling on reported errors so a pathological input cannot spin. Matches the
// parser's own limit.
constexpr std::size_t kMaxErrors = 20;

class Checker {
public:
    explicit Checker(DiagnosticEngine &diags) : diags_(diags) {}

    bool run(ast::Module &module) {
        for (ast::FunctionDecl *fn : module.functions) declareFunction(*fn);
        for (ast::FunctionDecl *fn : module.functions) checkFunctionBody(*fn);
        checkImplicitMain(module);
        return !diags_.hasErrors();
    }

private:
    void err(SourceLocation loc, const llvm::Twine &message) {
        if (diags_.errorCount() >= kMaxErrors) return;
        diags_.error(loc, message);
    }

    // --- pass 1: signatures ---------------------------------------
    void declareFunction(const ast::FunctionDecl &fn) {
        if (fn.name == "main") {
            err(fn.loc,
                "'main' is defined automatically from the top-level statements; "
                "rename this function");
            return;
        }
        if (functions_.count(fn.name)) {
            err(fn.loc, llvm::Twine("function '") + fn.name +
                            "' is defined more than once");
            return;
        }
        functions_[fn.name] = fn.params.size();
    }

    // --- pass 2: bodies -----------------------------------------
    void checkFunctionBody(const ast::FunctionDecl &fn) {
        locals_.clear();
        for (const ast::Param &p : fn.params) locals_.insert(p.name);
        if (fn.body) checkBlock(*fn.body);
    }

    void checkImplicitMain(const ast::Module &module) {
        locals_.clear();
        for (ast::Stmt *s : module.topLevelStatements) checkStmt(*s);
    }

    void checkBlock(const ast::Block &block) {
        for (ast::Stmt *s : block.statements) checkStmt(*s);
    }

    void checkStmt(ast::Stmt &stmt) {
        switch (stmt.kind) {
        case ast::NodeKind::VarDeclStmt: {
            auto &v = static_cast<ast::VarDeclStmt &>(stmt);
            checkExpr(*v.init, /*stringAllowed=*/false);
            locals_.insert(v.name);  // in scope only after its initializer
            return;
        }
        case ast::NodeKind::AssignStmt: {
            auto &a = static_cast<ast::AssignStmt &>(stmt);
            checkExpr(*a.value, /*stringAllowed=*/false);
            if (!locals_.count(a.name))
                err(a.loc, llvm::Twine("assignment to undeclared variable '") +
                               a.name + "'");
            return;
        }
        case ast::NodeKind::ExprStmt:
            checkExpr(*static_cast<ast::ExprStmt &>(stmt).expr,
                      /*stringAllowed=*/false);
            return;
        case ast::NodeKind::IfStmt: {
            auto &i = static_cast<ast::IfStmt &>(stmt);
            checkExpr(*i.condition, /*stringAllowed=*/false);
            checkBlock(*i.thenBlock);
            if (i.elseBlock) checkBlock(*i.elseBlock);
            return;
        }
        case ast::NodeKind::WhileStmt: {
            auto &w = static_cast<ast::WhileStmt &>(stmt);
            checkExpr(*w.condition, /*stringAllowed=*/false);
            checkBlock(*w.body);
            return;
        }
        case ast::NodeKind::ReturnStmt: {
            auto &r = static_cast<ast::ReturnStmt &>(stmt);
            if (r.value) checkExpr(*r.value, /*stringAllowed=*/false);
            return;
        }
        case ast::NodeKind::Block:
            checkBlock(static_cast<ast::Block &>(stmt));
            return;
        default:
            err(stmt.loc, "internal: unexpected statement kind in sema");
            return;
        }
    }

    // `stringAllowed` is true only for the single direct argument of a
    // `print(...)` call - the one place a string literal may appear in v0.
    void checkExpr(ast::Expr &expr, bool stringAllowed) {
        switch (expr.kind) {
        case ast::NodeKind::IntLiteralExpr:
            return;
        case ast::NodeKind::StringLiteralExpr:
            if (!stringAllowed)
                err(expr.loc,
                    "a string literal can only be passed directly to print(...)");
            return;
        case ast::NodeKind::VarRefExpr: {
            auto &v = static_cast<ast::VarRefExpr &>(expr);
            if (!locals_.count(v.name))
                err(v.loc, llvm::Twine("use of undeclared variable '") + v.name +
                               "'");
            return;
        }
        case ast::NodeKind::UnaryExpr:
            checkExpr(*static_cast<ast::UnaryExpr &>(expr).operand,
                      /*stringAllowed=*/false);
            return;
        case ast::NodeKind::BinaryExpr: {
            auto &b = static_cast<ast::BinaryExpr &>(expr);
            checkExpr(*b.lhs, /*stringAllowed=*/false);
            checkExpr(*b.rhs, /*stringAllowed=*/false);
            return;
        }
        case ast::NodeKind::CallExpr:
            checkCall(static_cast<ast::CallExpr &>(expr));
            return;
        default:
            err(expr.loc, "internal: unexpected expression kind in sema");
            return;
        }
    }

    void checkCall(ast::CallExpr &call) {
        // `print` is a builtin identifier, not a user function.
        if (call.callee == "print") {
            if (call.args.size() != 1) {
                err(call.loc,
                    llvm::Twine("print expects exactly 1 argument but got ") +
                        llvm::Twine(call.args.size()));
                return;
            }
            checkExpr(*call.args[0], /*stringAllowed=*/true);
            return;
        }

        auto it = functions_.find(call.callee);
        if (it == functions_.end()) {
            err(call.loc, llvm::Twine("call to undefined function '") +
                              call.callee + "'");
            return;
        }
        const std::size_t want = it->second;
        if (want != call.args.size()) {
            err(call.loc, llvm::Twine("function '") + call.callee + "' expects " +
                              llvm::Twine(want) + " argument(s) but " +
                              llvm::Twine(call.args.size()) + " were given");
            return;
        }
        for (ast::Expr *a : call.args) checkExpr(*a, /*stringAllowed=*/false);
    }

    DiagnosticEngine &diags_;
    llvm::StringMap<std::size_t> functions_;  // name -> parameter count
    llvm::StringSet<> locals_;                // reset per function
};

}  // namespace

bool analyze(ast::Module &module, DiagnosticEngine &diags) {
    return Checker(diags).run(module);
}

}  // namespace jocky::sema
