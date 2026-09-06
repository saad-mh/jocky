// Semantic analysis. See jocky/sema/Sema.h.
//
// Two passes over the module:
//   1. resolve every function's signature (parameter and return types) so calls
//      check regardless of source order;
//   2. walk each body (and the implicit main's top-level statements) in source
//      order, resolving names and giving every expression a type.
//
// The scope model is JOCKY's from v0: no nested scopes. A `var` is visible for
// the rest of its function once its initializer has been checked.
//
// Types (the L0 milestone): `int` (i64), `char` (u8), `bool`, `double`,
// `float`, and the sized aliases `i8..i64` / `u8..u64`. Implicit conversions
// are widening only (`char -> int`, narrower-int -> wider-int of the same
// signedness, `int -> double`, `float -> double`); everything else needs an
// explicit `expr as T`. Where an implicit widening is needed, sema splices an
// `ast::ImplicitConversionExpr` into the tree so codegen just emits it.

#include "jocky/sema/Sema.h"

#include "jocky/Support/Diagnostic.h"
#include "jocky/ast/AST.h"

#include <llvm/ADT/SmallVector.h>
#include <llvm/ADT/StringMap.h>
#include <llvm/ADT/StringSwitch.h>
#include <llvm/ADT/Twine.h>

#include <cstddef>
#include <cstdint>
#include <limits>
#include <memory>
#include <utility>

namespace jocky::sema {

namespace {

constexpr std::size_t kMaxErrors = 20;

using ast::Type;

struct FnSig {
    llvm::SmallVector<Type, 4> params;
    Type ret;
};

class Checker {
public:
    Checker(ast::Module &module, DiagnosticEngine &diags)
        : module_(module), diags_(diags) {}

    bool run() {
        for (ast::FunctionDecl *fn : module_.functions) declareFunction(*fn);
        for (ast::FunctionDecl *fn : module_.functions) checkFunctionBody(*fn);
        checkImplicitMain();
        return !diags_.hasErrors();
    }

private:
    // infra
    template <typename T, typename... Args>
    T *make(Args &&...args) {
        auto owned = std::make_unique<T>(std::forward<Args>(args)...);
        T *raw = owned.get();
        module_.arena.push_back(std::move(owned));
        return raw;
    }

    void err(SourceLocation loc, const llvm::Twine &message) {
        if (diags_.errorCount() >= kMaxErrors) return;
        diags_.error(loc, message);
    }

    // type res
    Type resolveType(const ast::TypeExpr *te) {
        switch (te->form) {
        case ast::TypeExpr::Form::Name:
            break;
        case ast::TypeExpr::Form::Slice: {
            Type elem = resolveType(te->element);
            if (elem.isError()) return Type::error();
            if (elem.isVoid()) {
                err(te->loc, "a slice element cannot be 'void'");
                return Type::error();
            }
            return Type::slice(elem);
        }
        case ast::TypeExpr::Form::Array: {
            Type elem = resolveType(te->element);
            std::uint64_t n = 0;
            const bool okN = constUint(*te->sizeExpr, n);
            if (elem.isError()) return Type::error();
            if (elem.isVoid()) {
                err(te->loc, "an array element cannot be 'void'");
                return Type::error();
            }
            if (!okN) {
                err(te->sizeExpr->loc,
                    "array length must be a constant non-negative integer");
                return Type::error();
            }
            return Type::array(elem, static_cast<unsigned>(n));
        }
        }

        const Type t = llvm::StringSwitch<Type>(te->name)
                           .Case("void", Type::voidTy())
                           .Case("bool", Type::boolTy())
                           .Case("int", Type::intTy())
                           .Case("char", Type::charTy())
                           .Case("i8", Type::integer(8, true))
                           .Case("i16", Type::integer(16, true))
                           .Case("i32", Type::integer(32, true))
                           .Case("i64", Type::integer(64, true))
                           .Case("u8", Type::integer(8, false))
                           .Case("u16", Type::integer(16, false))
                           .Case("u32", Type::integer(32, false))
                           .Case("u64", Type::integer(64, false))
                           .Case("float", Type::f32())
                           .Case("double", Type::f64())
                           .Default(Type::error());
        if (t.isError())
            err(te->loc, llvm::Twine("unknown type '") + te->name + "'");
        return t;
    }

    // A minimal compile-time evaluator for an array length: integer literals
    // and `+ - * / %` over them, plus parenthesised / cast forms. Enough for
    // `char[4096]`, `int[N*2]`. Returns false if `e` is not foldable or is
    // negative.
    static bool constUint(const ast::Expr &e, std::uint64_t &out) {
        switch (e.kind) {
        case ast::NodeKind::IntLiteralExpr: {
            const auto &n = static_cast<const ast::IntLiteralExpr &>(e);
            if (n.value < 0) return false;
            out = static_cast<std::uint64_t>(n.value);
            return true;
        }
        case ast::NodeKind::CastExpr:
            return constUint(*static_cast<const ast::CastExpr &>(e).operand, out);
        case ast::NodeKind::BinaryExpr: {
            const auto &b = static_cast<const ast::BinaryExpr &>(e);
            std::uint64_t l = 0, r = 0;
            if (!constUint(*b.lhs, l) || !constUint(*b.rhs, r)) return false;
            switch (b.op) {
            case ast::BinaryOp::Add: out = l + r; return true;
            case ast::BinaryOp::Sub: if (r > l) return false; out = l - r; return true;
            case ast::BinaryOp::Mul: out = l * r; return true;
            case ast::BinaryOp::Div: if (r == 0) return false; out = l / r; return true;
            case ast::BinaryOp::Mod: if (r == 0) return false; out = l % r; return true;
            default: return false;
            }
        }
        default:
            return false;
        }
    }

    // Widening conversions the language performs without a cast.
    static bool implicitlyConvertible(Type from, Type to) {
        if (from.isError() || to.isError()) return true;  // suppress cascades
        if (from == to) return true;
        if (from == Type::charTy() && to == Type::intTy()) return true;
        if (from.isInteger() && to.isInteger() &&
            from.isSigned == to.isSigned && to.bits > from.bits)
            return true;
        if (from == Type::intTy() && to == Type::f64()) return true;
        if (from == Type::f32() && to == Type::f64()) return true;
        return false;
    }

    // A `char[N]` or `char[]` - what `print` renders as a string.
    static bool isCharSequence(Type t) {
        return (t.isArray() || t.isSlice()) && t.elem() == Type::charTy();
    }

    // What `expr as T` accepts: any scalar to any other scalar.
    static bool explicitlyConvertible(Type from, Type to) {
        if (from.isError() || to.isError()) return true;
        const bool fromScalar = from.isNumeric() || from.isBool();
        const bool toScalar = to.isNumeric() || to.isBool();
        return fromScalar && toScalar;
    }

    // A bare integer literal (`0`, `-1`) has no fixed type: it takes whatever
    // its context needs, as long as its value fits (L0.3). If `e` is such a
    // literal - or the negation of one - and `target` is a numeric type big
    // enough, retype it in place and return true.
    static bool adaptIntLiteral(ast::Expr &e, Type target) {
        if (!target.isNumeric()) return false;

        ast::IntLiteralExpr *lit = nullptr;
        bool negated = false;
        if (e.kind == ast::NodeKind::IntLiteralExpr) {
            lit = static_cast<ast::IntLiteralExpr *>(&e);
        } else if (e.kind == ast::NodeKind::UnaryExpr) {
            auto &u = static_cast<ast::UnaryExpr &>(e);
            if (u.op == ast::UnaryOp::Neg &&
                u.operand->kind == ast::NodeKind::IntLiteralExpr) {
                lit = static_cast<ast::IntLiteralExpr *>(u.operand);
                negated = true;
            }
        }
        if (!lit || lit->suffixBits != 0) return false;  // bare literals only

        if (target.isInteger()) {
            const auto mag = static_cast<std::uint64_t>(lit->value);  // 0..i64max
            std::uint64_t limit;
            if (negated) {
                if (!target.isSigned) return false;
                limit = target.bits == 64 ? (1ULL << 63)
                                          : (1ULL << (target.bits - 1));
            } else if (target.isSigned) {
                limit = target.bits == 64
                            ? static_cast<std::uint64_t>(
                                  std::numeric_limits<std::int64_t>::max())
                            : (1ULL << (target.bits - 1)) - 1;
            } else {
                limit = target.bits == 64 ? ~0ULL
                                          : (1ULL << target.bits) - 1;
            }
            if (mag > limit) return false;
        }

        e.type = target;
        lit->type = target;
        return true;
    }

    // Splice an implicit widening of `slot` to `to` when one is needed and
    // allowed. Returns false (changing nothing) when `slot` is not implicitly
    // convertible to `to` - the caller then reports a type error.
    bool coerce(ast::Expr *&slot, Type to) {
        if (slot->type.isError() || to.isError() || slot->type == to)
            return true;
        if (adaptIntLiteral(*slot, to)) return true;  // literal becomes type `to`

        // A `T[N]` decays to a `T[]` (same element type).
        if (slot->type.isArray() && to.isSlice() &&
            slot->type.elem() == to.elem()) {
            auto *decay = make<ast::ArrayToSliceExpr>(slot->loc, slot);
            decay->type = to;
            slot = decay;
            return true;
        }

        if (!implicitlyConvertible(slot->type, to)) return false;
        auto *conv = make<ast::ImplicitConversionExpr>(slot->loc, slot);
        conv->type = to;
        slot = conv;
        return true;
    }

    // pass 1: signatures
    void declareFunction(ast::FunctionDecl &fn) {
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

        FnSig sig;
        for (ast::Param &p : fn.params) {
            if (!p.typeAnnotation) {
                err(p.loc,
                    llvm::Twine("parameter '") + p.name + "' needs a type");
                p.type = Type::error();
            } else {
                p.type = resolveType(p.typeAnnotation);
                if (p.type.isVoid()) {
                    err(p.typeAnnotation->loc,
                        "a parameter cannot have type 'void'");
                    p.type = Type::error();
                }
            }
            sig.params.push_back(p.type);
        }

        fn.resolvedReturn =
            fn.returnType ? resolveType(fn.returnType) : Type::intTy();
        sig.ret = fn.resolvedReturn;
        functions_[fn.name] = std::move(sig);
    }

    // pass 2: bodies
    void checkFunctionBody(ast::FunctionDecl &fn) {
        locals_.clear();
        for (const ast::Param &p : fn.params) locals_[p.name] = p.type;
        currentReturn_ = fn.resolvedReturn;
        if (fn.body) checkBlock(*fn.body);
    }

    void checkImplicitMain() {
        locals_.clear();
        currentReturn_ = Type::intTy();
        for (ast::Stmt *s : module_.topLevelStatements) checkStmt(*s);
    }

    void checkBlock(ast::Block &block) {
        for (ast::Stmt *s : block.statements) checkStmt(*s);
    }

    void checkStmt(ast::Stmt &stmt) {
        switch (stmt.kind) {
        case ast::NodeKind::VarDeclStmt:
            return checkVarDecl(static_cast<ast::VarDeclStmt &>(stmt));
        case ast::NodeKind::AssignStmt:
            return checkAssign(static_cast<ast::AssignStmt &>(stmt));
        case ast::NodeKind::ExprStmt:
            checkExpr(*static_cast<ast::ExprStmt &>(stmt).expr);  // void is fine (?)
            return;
        case ast::NodeKind::IfStmt: {
            auto &i = static_cast<ast::IfStmt &>(stmt);
            checkCondition(*i.condition);
            checkBlock(*i.thenBlock);
            if (i.elseBlock) checkBlock(*i.elseBlock);
            return;
        }
        case ast::NodeKind::WhileStmt: {
            auto &w = static_cast<ast::WhileStmt &>(stmt);
            checkCondition(*w.condition);
            checkBlock(*w.body);
            return;
        }
        case ast::NodeKind::ReturnStmt:
            return checkReturn(static_cast<ast::ReturnStmt &>(stmt));
        case ast::NodeKind::Block:
            return checkBlock(static_cast<ast::Block &>(stmt));
        default:
            err(stmt.loc, "internal: unexpected statement kind in sema");
        }
    }

    void checkVarDecl(ast::VarDeclStmt &v) {
        Type ann = Type::error();
        if (v.typeAnnotation) {
            ann = resolveType(v.typeAnnotation);
            if (ann.isVoid()) {
                err(v.typeAnnotation->loc, "a variable cannot have type 'void'");
                ann = Type::error();
            }
        }

        if (!v.init) {
            // `var buf: char[4096];` - annotated, storage left unset. A slice is
            // a borrowed view, so it has nothing to leave unset.
            if (ann.isSlice())
                err(v.loc, llvm::Twine("a slice variable ('") + v.name +
                               "') must be given an initializer");
            v.declaredType = ann;
            locals_[v.name] = v.declaredType;
            return;
        }

        const Type initT = checkExpr(*v.init, ann);

        if (v.typeAnnotation) {
            v.declaredType = ann;
            if (!ann.isError() && !initT.isError() && !coerce(v.init, ann))
                err(v.init->loc,
                    llvm::Twine("cannot initialize '") + v.name + "' of type " +
                        ann.name() + " from a value of type " + initT.name() +
                        " (add an explicit `as " + ann.name() + "`)");
        } else if (initT.isError() || initT.isVoid()) {
            err(v.loc, llvm::Twine("cannot infer type of '") + v.name +
                           "' from its initializer");
            v.declaredType = Type::error();
        } else {
            v.declaredType = initT;
        }

        locals_[v.name] = v.declaredType;
    }

    void checkAssign(ast::AssignStmt &a) {
        const Type targetT = checkExpr(*a.target);
        if (!isLValue(*a.target)) {
            if (!targetT.isError())
                err(a.target->loc, "the left side of '=' is not assignable");
            checkExpr(*a.value);
            return;
        }

        const Type valT = checkExpr(*a.value, targetT);
        if (!targetT.isError() && !valT.isError() && !coerce(a.value, targetT))
            err(a.value->loc,
                llvm::Twine("cannot assign a value of type ") + valT.name() +
                    " to a target of type " + targetT.name() +
                    " (add an explicit `as " + targetT.name() + "`)");
    }

    // A storable location: a variable, or an element of an array/slice.
    static bool isLValue(const ast::Expr &e) {
        return e.kind == ast::NodeKind::VarRefExpr ||
               e.kind == ast::NodeKind::IndexExpr;
    }

    void checkReturn(ast::ReturnStmt &r) {
        if (!r.value) return;  // bare `return;` -> the zero value / nothing

        const Type vt = checkExpr(*r.value);
        if (vt.isError()) return;

        if (currentReturn_.isVoid()) {
            err(r.value->loc,
                "returning a value from a function declared `-> void`");
            return;
        }
        if (!currentReturn_.isError() && !coerce(r.value, currentReturn_))
            err(r.value->loc, llvm::Twine("returning `") + vt.name() +
                                  "` from a function declared `-> " +
                                  currentReturn_.name() + "`");
    }

    void checkCondition(ast::Expr &e) {
        const Type t = checkExpr(e);
        if (t.isError() || t.isBool() || t.isInteger()) return;
        err(e.loc, llvm::Twine("condition must be a bool or an integer, not ") +
                       t.name());
    }

    // `expected` is an optional hint from the context (a var's declared type, a
    // parameter type, ...). Only array literals use it, to type their elements.
    Type checkExpr(ast::Expr &e, Type expected = Type::error()) {
        const Type t = computeType(e, expected);
        e.type = t;
        return t;
    }

    Type computeType(ast::Expr &e, Type expected) {
        switch (e.kind) {
        case ast::NodeKind::IntLiteralExpr: {
            const auto &n = static_cast<const ast::IntLiteralExpr &>(e);
            return n.suffixBits == 0
                       ? Type::intTy()
                       : Type::integer(n.suffixBits, n.suffixSigned);
        }
        case ast::NodeKind::FloatLiteralExpr:
            return static_cast<const ast::FloatLiteralExpr &>(e).isF32
                       ? Type::f32()
                       : Type::f64();
        case ast::NodeKind::CharLiteralExpr:
            return Type::charTy();
        case ast::NodeKind::BoolLiteralExpr:
            return Type::boolTy();
        case ast::NodeKind::StringLiteralExpr:
            // A string literal is a `char[len + 1]`, NUL-terminated (L0.7). It
            // decays to `char[]` like any other array.
            return Type::array(
                Type::charTy(),
                static_cast<unsigned>(
                    static_cast<const ast::StringLiteralExpr &>(e).value.size() +
                    1));
        case ast::NodeKind::VarRefExpr: {
            const auto &v = static_cast<const ast::VarRefExpr &>(e);
            auto it = locals_.find(v.name);
            if (it == locals_.end()) {
                err(v.loc, llvm::Twine("use of undeclared variable '") + v.name +
                               "'");
                return Type::error();
            }
            return it->second;
        }
        case ast::NodeKind::UnaryExpr: {
            auto &u = static_cast<ast::UnaryExpr &>(e);
            const Type ot = checkExpr(*u.operand);
            if (ot.isError()) return Type::error();
            if (!ot.isNumeric()) {
                err(u.loc, llvm::Twine("unary '-' needs a number, not ") +
                               ot.name());
                return Type::error();
            }
            return ot;
        }
        case ast::NodeKind::BinaryExpr:
            return checkBinary(static_cast<ast::BinaryExpr &>(e));
        case ast::NodeKind::CallExpr:
            return checkCall(static_cast<ast::CallExpr &>(e));
        case ast::NodeKind::CastExpr:
            return checkCast(static_cast<ast::CastExpr &>(e));
        case ast::NodeKind::ImplicitConversionExpr:
        case ast::NodeKind::ArrayToSliceExpr:
            return e.type;  // sema built it; the type is already right
        case ast::NodeKind::ArrayLiteralExpr:
            return checkArrayLiteral(static_cast<ast::ArrayLiteralExpr &>(e),
                                     expected);
        case ast::NodeKind::IndexExpr:
            return checkIndex(static_cast<ast::IndexExpr &>(e));
        case ast::NodeKind::SliceExpr:
            return checkSlice(static_cast<ast::SliceExpr &>(e));
        case ast::NodeKind::MemberExpr:
            return checkMember(static_cast<ast::MemberExpr &>(e));
        default:
            err(e.loc, "internal: unexpected expression kind in sema");
            return Type::error();
        }
    }

    // `[a, b, c]`. With an array/slice `expected` type, each element is checked
    // toward that element type; otherwise the first element sets it.
    Type checkArrayLiteral(ast::ArrayLiteralExpr &lit, Type expected) {
        if (lit.elements.empty()) {
            if (expected.isArray() || expected.isSlice())
                return Type::array(expected.elem(), 0);
            err(lit.loc, "cannot infer the element type of an empty array "
                         "literal (annotate the variable)");
            return Type::error();
        }

        Type elemHint = Type::error();
        if (expected.isArray() || expected.isSlice()) elemHint = expected.elem();

        Type elemT = elemHint;
        for (std::size_t i = 0; i < lit.elements.size(); ++i) {
            const Type et = checkExpr(*lit.elements[i], elemHint);
            if (et.isError()) return Type::error();
            if (i == 0 && elemT.isError()) elemT = et;
            if (!coerce(lit.elements[i], elemT)) {
                err(lit.elements[i]->loc,
                    llvm::Twine("array element ") + llvm::Twine(i) +
                        " has type " + et.name() + " but " + elemT.name() +
                        " was expected");
                return Type::error();
            }
        }
        return Type::array(elemT, static_cast<unsigned>(lit.elements.size()));
    }

    Type checkIndex(ast::IndexExpr &e) {
        const Type baseT = checkExpr(*e.base);
        const Type idxT = checkExpr(*e.index);
        if (baseT.isError()) return Type::error();
        if (!baseT.isArray() && !baseT.isSlice()) {
            err(e.loc, llvm::Twine("cannot index a value of type ") +
                           baseT.name());
            return Type::error();
        }
        if (!idxT.isError() && !idxT.isInteger() &&
            !adaptIntLiteral(*e.index, Type::intTy())) {
            err(e.index->loc, llvm::Twine("an array index must be an integer, "
                                          "not ") +
                                  idxT.name());
        }
        coerce(e.index, Type::intTy());
        return baseT.elem();
    }

    Type checkSlice(ast::SliceExpr &e) {
        const Type baseT = checkExpr(*e.base);
        if (e.lo) {
            checkExpr(*e.lo);
            coerce(e.lo, Type::intTy());
        }
        if (e.hi) {
            checkExpr(*e.hi);
            coerce(e.hi, Type::intTy());
        }
        if (baseT.isError()) return Type::error();
        if (!baseT.isArray() && !baseT.isSlice()) {
            err(e.loc, llvm::Twine("cannot slice a value of type ") +
                           baseT.name());
            return Type::error();
        }
        return Type::slice(baseT.elem());
    }

    Type checkMember(ast::MemberExpr &e) {
        const Type baseT = checkExpr(*e.base);
        if (baseT.isError()) return Type::error();
        if (e.member != "len") {
            err(e.loc, llvm::Twine("type ") + baseT.name() + " has no member '" +
                           e.member + "'");
            return Type::error();
        }
        if (!baseT.isArray() && !baseT.isSlice()) {
            err(e.loc, llvm::Twine("'.len' needs an array or a slice, not ") +
                           baseT.name());
            return Type::error();
        }
        return Type::intTy();
    }

    Type checkBinary(ast::BinaryExpr &b) {
        Type lt = checkExpr(*b.lhs);
        Type rt = checkExpr(*b.rhs);
        if (lt.isError() || rt.isError()) return Type::error();

        if (!lt.isNumeric() || !rt.isNumeric()) {
            err(b.loc, llvm::Twine("operator '") + ast::binaryOpSymbol(b.op) +
                           "' needs numbers, not " + lt.name() + " and " +
                           rt.name());
            return Type::error();
        }

        // a bare integer literal on one side takes the other side's type
        if (lt != rt) {
            if (adaptIntLiteral(*b.lhs, rt))
                lt = rt;
            else if (adaptIntLiteral(*b.rhs, lt))
                rt = lt;
        }

        Type common;
        if (lt == rt)
            common = lt;
        else if (implicitlyConvertible(lt, rt))
            common = rt;
        else if (implicitlyConvertible(rt, lt))
            common = lt;
        else {
            err(b.loc, llvm::Twine("operands of '") + ast::binaryOpSymbol(b.op) +
                           "' have incompatible types " + lt.name() + " and " +
                           rt.name() + " (add an explicit `as`)");
            return Type::error();
        }

        if (b.op == ast::BinaryOp::Mod && !common.isInteger()) {
            err(b.loc, "'%' needs integer operands");
            return Type::error();
        }

        coerce(b.lhs, common);
        coerce(b.rhs, common);
        return ast::isComparison(b.op) ? Type::boolTy() : common;
    }

    Type checkCall(ast::CallExpr &c) {
        if (c.callee == "print") {
            if (c.args.size() != 1) {
                err(c.loc,
                    llvm::Twine("print expects exactly 1 argument but got ") +
                        llvm::Twine(c.args.size()));
                return Type::intTy();
            }
            const Type at = checkExpr(*c.args[0]);
            const bool printable = at.isError() || at.isScalar() ||
                                   isCharSequence(at);
            if (!printable)
                err(c.args[0]->loc,
                    llvm::Twine("print cannot format a value of type ") +
                        at.name());
            return Type::intTy();  // print(...) evaluates to 0
        }

        auto it = functions_.find(c.callee);
        if (it == functions_.end()) {
            err(c.loc, llvm::Twine("call to undefined function '") + c.callee +
                           "'");
            for (ast::Expr *a : c.args) checkExpr(*a);
            return Type::error();
        }

        const FnSig &sig = it->second;
        if (sig.params.size() != c.args.size()) {
            err(c.loc, llvm::Twine("function '") + c.callee + "' expects " +
                           llvm::Twine(sig.params.size()) + " argument(s) but " +
                           llvm::Twine(c.args.size()) + " were given");
            for (ast::Expr *a : c.args) checkExpr(*a);
            return sig.ret;
        }

        for (std::size_t i = 0; i < c.args.size(); ++i) {
            const Type at = checkExpr(*c.args[i]);
            const Type pt = sig.params[i];
            if (!at.isError() && !pt.isError() && !coerce(c.args[i], pt))
                err(c.args[i]->loc,
                    llvm::Twine("argument ") + llvm::Twine(i + 1) + " to '" +
                        c.callee + "' has type " + at.name() + " but " +
                        pt.name() + " was expected (add an explicit `as " +
                        pt.name() + "`)");
        }
        return sig.ret;
    }

    Type checkCast(ast::CastExpr &c) {
        const Type from = checkExpr(*c.operand);
        const Type to = resolveType(c.targetType);
        if (from.isError() || to.isError()) return to;

        if (to.isVoid()) {
            err(c.loc, "cannot cast to 'void'");
            return Type::error();
        }
        // A widening that would have happened implicitly is always fine; so is
        // any scalar<->scalar reinterpretation.
        if (implicitlyConvertible(from, to) || explicitlyConvertible(from, to))
            return to;

        err(c.loc, llvm::Twine("cannot cast ") + from.name() + " to " +
                       to.name());
        return Type::error();
    }

    ast::Module &module_;
    DiagnosticEngine &diags_;
    llvm::StringMap<FnSig> functions_;
    llvm::StringMap<Type> locals_;  // reset per function
    Type currentReturn_;
};

}  // namespace

bool analyze(ast::Module &module, DiagnosticEngine &diags) {
    return Checker(module, diags).run();
}

}  // namespace jocky::sema
