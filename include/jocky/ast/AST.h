// The abstract syntax tree the parser builds.
//
// Memory model: an ast::Module owns every node through an arena (a vector of
// unique_ptr<Node>). Nodes point at each other with plain, non-owning
// pointers. When the Module is destroyed, every node goes with it. Do not free
// nodes by hand and do not keep node pointers past the Module's lifetime.

#ifndef JOCKY_AST_AST_H
#define JOCKY_AST_AST_H

#include "jocky/Support/SourceLocation.h"
#include "jocky/ast/Type.h"

#include <cstdint>
#include <memory>
#include <string>
#include <utility>
#include <vector>

namespace jocky::ast {

enum class NodeKind {
    // Expressions.
    IntLiteralExpr,
    FloatLiteralExpr,
    CharLiteralExpr,
    BoolLiteralExpr,
    StringLiteralExpr,
    VarRefExpr,
    UnaryExpr,
    BinaryExpr,
    CallExpr,
    CastExpr,             // `expr as T` (written by the user)
    ImplicitConversionExpr,  // inserted by sema at an allowed widening
    // Statements.
    VarDeclStmt,
    AssignStmt,
    ExprStmt,
    IfStmt,
    WhileStmt,
    ReturnStmt,
    Block,
    // Type syntax.
    TypeExpr,
    // Top level.
    FunctionDecl,
    Module,
};

enum class UnaryOp {
    Neg,  // -x
};

enum class BinaryOp {
    Add, Sub, Mul, Div, Mod,   // + - * / %
    Eq, Ne, Lt, Le, Gt, Ge,    // == != < <= > >=
};

// Human-readable names, for the AST dump and tests.
const char *unaryOpName(UnaryOp op);
const char *binaryOpName(BinaryOp op);

// The operator's source spelling ("+", "==", ...), for diagnostics.
const char *binaryOpSymbol(BinaryOp op);

// True for == != < <= > >= (the ops that yield `bool`).
bool isComparison(BinaryOp op);

// --- Base -------------------------------------------------------------

struct Node {
    NodeKind kind;
    SourceLocation loc;

    Node(NodeKind k, SourceLocation l) : kind(k), loc(l) {}
    virtual ~Node();  // defined out-of-line in AST.cpp (the vtable anchor)

    Node(const Node &) = delete;
    Node &operator=(const Node &) = delete;
};

struct Expr : Node {
    using Node::Node;

    // Filled in by the semantic-analysis stage (src/sema/). Every expression
    // that survives sema carries its resolved type here; codegen reads it and
    // never re-derives one. Stays TypeKind::Error until sema runs (or when the
    // expression itself failed to check).
    Type type;
};

struct Stmt : Node {
    using Node::Node;
};

// --- Expressions ----------------------------------------------------

struct IntLiteralExpr : Expr {
    std::int64_t value;
    // An explicit type suffix (`42u32`, `-1i8`). `suffixBits == 0` means the
    // literal was bare and defaults to `int`.
    unsigned suffixBits = 0;      // 8 / 16 / 32 / 64
    bool suffixSigned = true;
    IntLiteralExpr(SourceLocation l, std::int64_t v)
        : Expr(NodeKind::IntLiteralExpr, l), value(v) {}
};

struct FloatLiteralExpr : Expr {
    double value;
    bool isF32;  // had an `f` suffix -> `float`; otherwise `double`
    FloatLiteralExpr(SourceLocation l, double v, bool f32)
        : Expr(NodeKind::FloatLiteralExpr, l), value(v), isF32(f32) {}
};

struct CharLiteralExpr : Expr {
    std::uint8_t value;
    CharLiteralExpr(SourceLocation l, std::uint8_t v)
        : Expr(NodeKind::CharLiteralExpr, l), value(v) {}
};

struct BoolLiteralExpr : Expr {
    bool value;
    BoolLiteralExpr(SourceLocation l, bool v)
        : Expr(NodeKind::BoolLiteralExpr, l), value(v) {}
};

struct StringLiteralExpr : Expr {
    std::string value;  // already-decoded bytes
    StringLiteralExpr(SourceLocation l, std::string v)
        : Expr(NodeKind::StringLiteralExpr, l), value(std::move(v)) {}
};

struct VarRefExpr : Expr {
    std::string name;
    VarRefExpr(SourceLocation l, std::string n)
        : Expr(NodeKind::VarRefExpr, l), name(std::move(n)) {}
};

struct UnaryExpr : Expr {
    UnaryOp op;
    Expr *operand;
    UnaryExpr(SourceLocation l, UnaryOp o, Expr *e)
        : Expr(NodeKind::UnaryExpr, l), op(o), operand(e) {}
};

struct BinaryExpr : Expr {
    BinaryOp op;
    Expr *lhs;
    Expr *rhs;
    BinaryExpr(SourceLocation l, BinaryOp o, Expr *a, Expr *b)
        : Expr(NodeKind::BinaryExpr, l), op(o), lhs(a), rhs(b) {}
};

struct CallExpr : Expr {
    std::string callee;
    std::vector<Expr *> args;
    CallExpr(SourceLocation l, std::string c)
        : Expr(NodeKind::CallExpr, l), callee(std::move(c)) {}
};

// The type written on the right of `expr as T`, on a parameter (`p: T`), or on a
// `var` (`var x: T = ...`). Only a bare name for now; array / pointer / slice
// forms arrive in later milestones. Sema resolves `name` to an `ast::Type`.
struct TypeExpr : Node {
    std::string name;
    TypeExpr(SourceLocation l, std::string n)
        : Node(NodeKind::TypeExpr, l), name(std::move(n)) {}
};

// `operand as targetType`, written by the programmer. Sema checks the cast is
// one the language permits and records the result type on `Expr::type`.
struct CastExpr : Expr {
    Expr *operand;
    TypeExpr *targetType;
    CastExpr(SourceLocation l, Expr *e, TypeExpr *t)
        : Expr(NodeKind::CastExpr, l), operand(e), targetType(t) {}
};

// A widening conversion sema inserts where the language allows one implicitly
// (e.g. `char` -> `int`, `int` -> `double`). The destination type is on
// `Expr::type`; codegen emits the matching sext/zext/sitofp/fpext.
struct ImplicitConversionExpr : Expr {
    Expr *operand;
    ImplicitConversionExpr(SourceLocation l, Expr *e)
        : Expr(NodeKind::ImplicitConversionExpr, l), operand(e) {}
};

// --- Statements ---------------------------------------------------

struct VarDeclStmt : Stmt {
    std::string name;
    Expr *init;  // always present (`var x = expr;`)
    TypeExpr *typeAnnotation = nullptr;  // `var x: T = ...`; null means "infer"
    Type declaredType;                   // resolved by sema
    VarDeclStmt(SourceLocation l, std::string n, Expr *e)
        : Stmt(NodeKind::VarDeclStmt, l), name(std::move(n)), init(e) {}
};

struct AssignStmt : Stmt {
    std::string name;
    Expr *value;
    AssignStmt(SourceLocation l, std::string n, Expr *e)
        : Stmt(NodeKind::AssignStmt, l), name(std::move(n)), value(e) {}
};

struct ExprStmt : Stmt {
    Expr *expr;
    ExprStmt(SourceLocation l, Expr *e) : Stmt(NodeKind::ExprStmt, l), expr(e) {}
};

struct Block : Stmt {
    std::vector<Stmt *> statements;
    explicit Block(SourceLocation l) : Stmt(NodeKind::Block, l) {}
};

struct IfStmt : Stmt {
    Expr *condition;
    Block *thenBlock;
    Block *elseBlock;  // null if there is no `else`. An `else if` is stored as a
                       // Block holding a single IfStmt.
    IfStmt(SourceLocation l, Expr *c, Block *t, Block *e)
        : Stmt(NodeKind::IfStmt, l), condition(c), thenBlock(t), elseBlock(e) {}
};

struct WhileStmt : Stmt {
    Expr *condition;
    Block *body;
    WhileStmt(SourceLocation l, Expr *c, Block *b)
        : Stmt(NodeKind::WhileStmt, l), condition(c), body(b) {}
};

struct ReturnStmt : Stmt {
    Expr *value;  // null means `return;`, which behaves like `return 0;`
    ReturnStmt(SourceLocation l, Expr *v)
        : Stmt(NodeKind::ReturnStmt, l), value(v) {}
};

// --- Top level -------------------------------------------------

struct Param {
    std::string name;
    SourceLocation loc;
    TypeExpr *typeAnnotation = nullptr;  // `p: T`
    Type type;                           // resolved by sema
};

struct FunctionDecl : Node {
    std::string name;
    std::vector<Param> params;
    TypeExpr *returnType = nullptr;  // the `-> T` annotation; null means `-> int`
    Type resolvedReturn;             // resolved by sema
    Block *body;
    FunctionDecl(SourceLocation l, std::string n)
        : Node(NodeKind::FunctionDecl, l), name(std::move(n)), body(nullptr) {}
};

struct Module : Node {
    std::vector<FunctionDecl *> functions;
    std::vector<Stmt *> topLevelStatements;  // run as the body of an implicit main

    // Owns every node above. See the file header.
    std::vector<std::unique_ptr<Node>> arena;

    Module() : Node(NodeKind::Module, SourceLocation{}) {}
};

}  // namespace jocky::ast

#endif  // JOCKY_AST_AST_H
