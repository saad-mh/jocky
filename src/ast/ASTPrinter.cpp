#include "jocky/ast/ASTPrinter.h"

#include "jocky/Support/StringEscape.h"
#include "jocky/ast/AST.h"

#include <llvm/Support/raw_ostream.h>

namespace jocky::ast {

namespace {

// Renders a TypeExpr the way it was written: "int", "char[4096]", "int[]".
std::string typeName(const TypeExpr *t) {
    if (!t) return "?";
    switch (t->form) {
    case TypeExpr::Form::Name:
        return t->name;
    case TypeExpr::Form::Array:
        return typeName(t->element) + "[N]";
    case TypeExpr::Form::Slice:
        return typeName(t->element) + "[]";
    }
    return "?";
}

class Printer {
public:
    explicit Printer(llvm::raw_ostream &os) : os_(os) {}

    void module(const Module &m) {
        line("(module");
        indent_ += 1;
        for (const FunctionDecl *fn : m.functions) function(*fn);
        if (!m.topLevelStatements.empty()) {
            line("(toplevel");
            indent_ += 1;
            for (const Stmt *s : m.topLevelStatements) stmt(*s);
            indent_ -= 1;
            line(")");
        }
        indent_ -= 1;
        line(")");
    }

private:
    void function(const FunctionDecl &fn) {
        std::string head = "(func " + fn.name + " (";
        for (std::size_t i = 0; i < fn.params.size(); ++i) {
            if (i) head += " ";
            head += fn.params[i].name;
            if (fn.params[i].typeAnnotation)
                head += ":" + typeName(fn.params[i].typeAnnotation);
        }
        head += ")";
        if (fn.returnType) head += " -> " + typeName(fn.returnType);
        line(head);
        indent_ += 1;
        if (fn.body) block(*fn.body);
        indent_ -= 1;
        line(")");
    }

    void block(const Block &b) {
        line("(block");
        indent_ += 1;
        for (const Stmt *s : b.statements) stmt(*s);
        indent_ -= 1;
        line(")");
    }

    void stmt(const Stmt &s) {
        switch (s.kind) {
        case NodeKind::VarDeclStmt: {
            const auto &v = static_cast<const VarDeclStmt &>(s);
            std::string head = "(vardecl " + v.name;
            if (v.typeAnnotation) head += ":" + typeName(v.typeAnnotation);
            line(head);
            indent_ += 1;
            if (v.init)
                expr(*v.init);
            else
                line("(uninit)");
            indent_ -= 1;
            line(")");
            break;
        }
        case NodeKind::AssignStmt: {
            const auto &a = static_cast<const AssignStmt &>(s);
            line("(assign");
            indent_ += 1;
            expr(*a.target);
            expr(*a.value);
            indent_ -= 1;
            line(")");
            break;
        }
        case NodeKind::ExprStmt: {
            const auto &e = static_cast<const ExprStmt &>(s);
            line("(exprstmt");
            indent_ += 1;
            expr(*e.expr);
            indent_ -= 1;
            line(")");
            break;
        }
        case NodeKind::IfStmt: {
            const auto &i = static_cast<const IfStmt &>(s);
            line("(if");
            indent_ += 1;
            expr(*i.condition);
            block(*i.thenBlock);
            if (i.elseBlock) block(*i.elseBlock);
            indent_ -= 1;
            line(")");
            break;
        }
        case NodeKind::WhileStmt: {
            const auto &w = static_cast<const WhileStmt &>(s);
            line("(while");
            indent_ += 1;
            expr(*w.condition);
            block(*w.body);
            indent_ -= 1;
            line(")");
            break;
        }
        case NodeKind::ReturnStmt: {
            const auto &r = static_cast<const ReturnStmt &>(s);
            if (!r.value) {
                line("(return)");
                break;
            }
            line("(return");
            indent_ += 1;
            expr(*r.value);
            indent_ -= 1;
            line(")");
            break;
        }
        case NodeKind::Block:
            block(static_cast<const Block &>(s));
            break;
        default:
            line("(?stmt?)");
            break;
        }
    }

    // The resolved type, once sema has run: " :int", " :char[]", ... Empty when
    // the AST is dumped before sema, or when this node failed to check.
    static std::string ty(const Expr &e) {
        return e.type.isError() ? std::string() : " :" + e.type.name();
    }

    void expr(const Expr &e) {
        switch (e.kind) {
        case NodeKind::IntLiteralExpr: {
            const auto &n = static_cast<const IntLiteralExpr &>(e);
            std::string text = "(intlit " + std::to_string(n.value);
            if (n.suffixBits != 0)
                text += std::string(" ") + (n.suffixSigned ? "i" : "u") +
                        std::to_string(n.suffixBits);
            line(text + ty(e) + ")");
            break;
        }
        case NodeKind::FloatLiteralExpr: {
            const auto &n = static_cast<const FloatLiteralExpr &>(e);
            line("(floatlit " + std::to_string(n.value) + (n.isF32 ? "f" : "") +
                 ty(e) + ")");
            break;
        }
        case NodeKind::CharLiteralExpr: {
            const auto &n = static_cast<const CharLiteralExpr &>(e);
            line("(charlit " + std::to_string(static_cast<unsigned>(n.value)) +
                 ty(e) + ")");
            break;
        }
        case NodeKind::BoolLiteralExpr: {
            const auto &n = static_cast<const BoolLiteralExpr &>(e);
            line(std::string("(boollit ") + (n.value ? "true" : "false") +
                 ty(e) + ")");
            break;
        }
        case NodeKind::StringLiteralExpr: {
            const auto &n = static_cast<const StringLiteralExpr &>(e);
            line("(strlit " + encodeStringLiteral(n.value) + ty(e) + ")");
            break;
        }
        case NodeKind::CastExpr: {
            const auto &n = static_cast<const CastExpr &>(e);
            line("(cast " + typeName(n.targetType) + ty(e));
            indent_ += 1;
            expr(*n.operand);
            indent_ -= 1;
            line(")");
            break;
        }
        case NodeKind::ImplicitConversionExpr: {
            const auto &n = static_cast<const ImplicitConversionExpr &>(e);
            line("(convert" + ty(e));
            indent_ += 1;
            expr(*n.operand);
            indent_ -= 1;
            line(")");
            break;
        }
        case NodeKind::VarRefExpr: {
            const auto &n = static_cast<const VarRefExpr &>(e);
            line("(varref " + n.name + ty(e) + ")");
            break;
        }
        case NodeKind::UnaryExpr: {
            const auto &n = static_cast<const UnaryExpr &>(e);
            line(std::string("(unary ") + unaryOpName(n.op) + ty(e));
            indent_ += 1;
            expr(*n.operand);
            indent_ -= 1;
            line(")");
            break;
        }
        case NodeKind::BinaryExpr: {
            const auto &n = static_cast<const BinaryExpr &>(e);
            line(std::string("(binary ") + binaryOpName(n.op) + ty(e));
            indent_ += 1;
            expr(*n.lhs);
            expr(*n.rhs);
            indent_ -= 1;
            line(")");
            break;
        }
        case NodeKind::CallExpr: {
            const auto &n = static_cast<const CallExpr &>(e);
            line("(call " + n.callee + ty(e));
            indent_ += 1;
            for (const Expr *a : n.args) expr(*a);
            indent_ -= 1;
            line(")");
            break;
        }
        case NodeKind::ArrayLiteralExpr: {
            const auto &n = static_cast<const ArrayLiteralExpr &>(e);
            line("(arraylit" + ty(e));
            indent_ += 1;
            for (const Expr *el : n.elements) expr(*el);
            indent_ -= 1;
            line(")");
            break;
        }
        case NodeKind::IndexExpr: {
            const auto &n = static_cast<const IndexExpr &>(e);
            line("(index" + ty(e));
            indent_ += 1;
            expr(*n.base);
            expr(*n.index);
            indent_ -= 1;
            line(")");
            break;
        }
        case NodeKind::SliceExpr: {
            const auto &n = static_cast<const SliceExpr &>(e);
            line("(slice" + ty(e));
            indent_ += 1;
            expr(*n.base);
            line(n.lo ? "(lo" : "(lo -)");
            if (n.lo) {
                indent_ += 1;
                expr(*n.lo);
                indent_ -= 1;
                line(")");
            }
            line(n.hi ? "(hi" : "(hi -)");
            if (n.hi) {
                indent_ += 1;
                expr(*n.hi);
                indent_ -= 1;
                line(")");
            }
            indent_ -= 1;
            line(")");
            break;
        }
        case NodeKind::MemberExpr: {
            const auto &n = static_cast<const MemberExpr &>(e);
            line("(member " + n.member + ty(e));
            indent_ += 1;
            expr(*n.base);
            indent_ -= 1;
            line(")");
            break;
        }
        case NodeKind::ArrayToSliceExpr: {
            const auto &n = static_cast<const ArrayToSliceExpr &>(e);
            line("(decay" + ty(e));
            indent_ += 1;
            expr(*n.array);
            indent_ -= 1;
            line(")");
            break;
        }
        default:
            line("(?expr?)");
            break;
        }
    }

    void line(const std::string &text) {
        for (int i = 0; i < indent_; ++i) os_ << "  ";
        os_ << text << '\n';
    }

    llvm::raw_ostream &os_;
    int indent_ = 0;
};

}  // namespace

void printAST(llvm::raw_ostream &os, const Module &module) {
    Printer(os).module(module);
}

}  // namespace jocky::ast
