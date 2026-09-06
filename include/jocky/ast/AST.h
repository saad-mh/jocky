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
    ArrayLiteralExpr,    // [a, b, c]
    IndexExpr,           // base[i]
    SliceExpr,           // base[lo:hi]
    MemberExpr,          // base.member  (only `.len` for now)
    ArrayToSliceExpr,    // inserted by sema where a T[N] decays to a T[]
    NullLiteralExpr,     // null
    AddrOfExpr,          // &lvalue
    DerefExpr,           // *ptr
    SizeofExpr,          // sizeof(T) / sizeof(expr)
    OffsetofExpr,        // offsetof(Struct, field)
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
    StructDecl,
    ExternDecl,
    FunctionDecl,
    Module,
};

enum class UnaryOp {
    Neg,     // -x
    BitNot,  // ~x
};

enum class BinaryOp {
    Add, Sub, Mul, Div, Mod,        // + - * / %
    BitAnd, BitOr, BitXor,          // & | ^
    Shl, Shr,                       // << >>
    Eq, Ne, Lt, Le, Gt, Ge,        // == != < <= > >=
};

// Human-readable names, for the AST dump and tests.
const char *unaryOpName(UnaryOp op);
const char *binaryOpName(BinaryOp op);

// The operator's source spelling ("+", "==", ...), for diagnostics.
const char *binaryOpSymbol(BinaryOp op);

// True for == != < <= > >= (the ops that yield `bool`).
bool isComparison(BinaryOp op);

// Base

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

// Exprr

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
// `var` (`var x: T = ...`). A bare name (`int`, `u32`), a fixed array
// (`char[4096]`), or a slice (`char[]`). Sema resolves it to an `ast::Type`.
struct TypeExpr : Node {
    enum class Form { Name, Array, Slice, Pointer };
    Form form = Form::Name;
    std::string name;             // Form::Name  (`rawptr` is a name)
    TypeExpr *element = nullptr;  // Array / Slice element, or Pointer pointee
    Expr *sizeExpr = nullptr;     // Form::Array: a constant-integer expression

    TypeExpr(SourceLocation l, std::string n)
        : Node(NodeKind::TypeExpr, l), name(std::move(n)) {}
    TypeExpr(SourceLocation l, Form f, TypeExpr *elem, Expr *size)
        : Node(NodeKind::TypeExpr, l), form(f), element(elem), sizeExpr(size) {}
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

// `[a, b, c]` - a fixed-array value. Every element must be assignable to a
// common element type; the length is the element count.
struct ArrayLiteralExpr : Expr {
    std::vector<Expr *> elements;
    explicit ArrayLiteralExpr(SourceLocation l)
        : Expr(NodeKind::ArrayLiteralExpr, l) {}
};

// `base[index]` - one element of an array or slice. `index` is an integer;
// there is no bounds check (see L0.11).
struct IndexExpr : Expr {
    Expr *base;
    Expr *index;
    IndexExpr(SourceLocation l, Expr *b, Expr *i)
        : Expr(NodeKind::IndexExpr, l), base(b), index(i) {}
};

// `base[lo:hi]` - a sub-slice. Either bound may be omitted (`lo` defaults to 0,
// `hi` to `base.len`).
struct SliceExpr : Expr {
    Expr *base;
    Expr *lo;  // null -> 0
    Expr *hi;  // null -> base.len
    SliceExpr(SourceLocation l, Expr *b, Expr *lo_, Expr *hi_)
        : Expr(NodeKind::SliceExpr, l), base(b), lo(lo_), hi(hi_) {}
};

// `base.member` - only `len` for now: an array's or slice's length, as `int`.
struct MemberExpr : Expr {
    Expr *base;
    std::string member;
    MemberExpr(SourceLocation l, Expr *b, std::string m)
        : Expr(NodeKind::MemberExpr, l), base(b), member(std::move(m)) {}
};

// Inserted by sema where a `T[N]` value is used where a `T[]` is wanted: builds
// the `{ base, len }` pair. The slice type is on `Expr::type`.
struct ArrayToSliceExpr : Expr {
    Expr *array;
    ArrayToSliceExpr(SourceLocation l, Expr *a)
        : Expr(NodeKind::ArrayToSliceExpr, l), array(a) {}
};

// `null` - the null pointer. Types as `rawptr` and coerces to any pointer type.
struct NullLiteralExpr : Expr {
    explicit NullLiteralExpr(SourceLocation l)
        : Expr(NodeKind::NullLiteralExpr, l) {}
};

// `&lvalue` - a pointer to a variable, array element, or (later) struct field.
struct AddrOfExpr : Expr {
    Expr *operand;
    AddrOfExpr(SourceLocation l, Expr *e)
        : Expr(NodeKind::AddrOfExpr, l), operand(e) {}
};

// `*ptr` - reads through a pointer; also an lvalue (`*p = v`).
struct DerefExpr : Expr {
    Expr *operand;
    DerefExpr(SourceLocation l, Expr *e)
        : Expr(NodeKind::DerefExpr, l), operand(e) {}
};

// `sizeof(...)` - a compile-time `int`. Exactly one of `typeArg` / `exprArg` is
// set (the parser tries a type first, then falls back to an expression).
struct SizeofExpr : Expr {
    TypeExpr *typeArg = nullptr;
    Expr *exprArg = nullptr;
    Type measured;  // resolved by sema: the type whose size this is
    explicit SizeofExpr(SourceLocation l) : Expr(NodeKind::SizeofExpr, l) {}
};

// `offsetof(Struct, field)` - a compile-time `int` byte offset.
struct OffsetofExpr : Expr {
    std::string structName;
    std::string fieldName;
    unsigned long long resolvedOffset = 0;  // filled by sema
    OffsetofExpr(SourceLocation l, std::string s, std::string f)
        : Expr(NodeKind::OffsetofExpr, l), structName(std::move(s)),
          fieldName(std::move(f)) {}
};

// Statements

struct VarDeclStmt : Stmt {
    std::string name;
    Expr *init;  // null only for an annotated declaration with no initializer
                 // (`var buf: char[4096];`), which leaves the storage unset
    TypeExpr *typeAnnotation = nullptr;  // `var x: T = ...`; null means "infer"
    Type declaredType;                   // resolved by sema
    VarDeclStmt(SourceLocation l, std::string n, Expr *e)
        : Stmt(NodeKind::VarDeclStmt, l), name(std::move(n)), init(e) {}
};

struct AssignStmt : Stmt {
    Expr *target;  // an lvalue: a variable reference or an array/slice index
    Expr *value;
    AssignStmt(SourceLocation l, Expr *t, Expr *e)
        : Stmt(NodeKind::AssignStmt, l), target(t), value(e) {}
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

// Top Level

struct Param {
    std::string name;
    SourceLocation loc;
    TypeExpr *typeAnnotation = nullptr;  // `p: T`
    Type type;                           // resolved by sema
    bool isOut = false;                  // the `out` marker (extern params only)
};

// `extern "C" name(params) -> ret;` - a C function implemented elsewhere and
// resolved at link time. `...` at the end of the parameter list makes it
// varargs. No body.
struct ExternDecl : Node {
    std::string name;
    std::vector<Param> params;
    bool isVarArg = false;
    TypeExpr *returnType = nullptr;  // null means `-> int`
    Type resolvedReturn;            // resolved by sema
    ExternDecl(SourceLocation l, std::string n)
        : Node(NodeKind::ExternDecl, l), name(std::move(n)) {}
};

// `struct Name { field: T, ... }` - fields in declared order, C natural
// alignment, no reordering. Sema builds an `ast::StructInfo` from this.
struct FieldDecl {
    std::string name;
    SourceLocation loc;
    TypeExpr *typeAnnotation = nullptr;
};

struct StructDecl : Node {
    std::string name;
    std::vector<FieldDecl> fields;
    StructDecl(SourceLocation l, std::string n)
        : Node(NodeKind::StructDecl, l), name(std::move(n)) {}
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
    std::vector<StructDecl *> structs;
    std::vector<ExternDecl *> externs;
    std::vector<FunctionDecl *> functions;
    std::vector<std::string> linkLibs;  // `link "name";` pragmas
    std::vector<Stmt *> topLevelStatements;  // run as the body of an implicit main

    // Owns every node above. See the file header.
    std::vector<std::unique_ptr<Node>> arena;

    Module() : Node(NodeKind::Module, SourceLocation{}) {}
};

}  // namespace jocky::ast

#endif  // JOCKY_AST_AST_H
