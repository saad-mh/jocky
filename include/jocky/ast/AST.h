// The abstract syntax tree the parser builds.
//
// Memory model: an ast::Module owns every node through an arena (a vector of
// unique_ptr<Node>). Nodes point at each other with plain, non-owning
// pointers. When the Module is destroyed, every node goes with it. Do not free
// nodes by hand and do not keep node pointers past the Module's lifetime.

#ifndef JOCKY_AST_AST_H
#define JOCKY_AST_AST_H

#include "jocky/Support/SourceLocation.h"

#include <cstdint>
#include <memory>
#include <string>
#include <utility>
#include <vector>

namespace jocky::ast {

enum class NodeKind {
    // Expressions.
    IntLiteralExpr,
    StringLiteralExpr,
    VarRefExpr,
    UnaryExpr,
    BinaryExpr,
    CallExpr,
    // Statements.
    VarDeclStmt,
    AssignStmt,
    ExprStmt,
    IfStmt,
    WhileStmt,
    ReturnStmt,
    Block,
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
};

struct Stmt : Node {
    using Node::Node;
};

// --- Expressions ----------------------------------------------------

struct IntLiteralExpr : Expr {
    std::int64_t value;
    IntLiteralExpr(SourceLocation l, std::int64_t v)
        : Expr(NodeKind::IntLiteralExpr, l), value(v) {}
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

// --- Statements ---------------------------------------------------

struct VarDeclStmt : Stmt {
    std::string name;
    Expr *init;  // always present in v0 (`var x = expr;`)
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
};

struct FunctionDecl : Node {
    std::string name;
    std::vector<Param> params;  // every parameter is a 64-bit int in v0
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
