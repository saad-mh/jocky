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
// Types (the L0 milestone): `int` (i64), `char` (u8), `flag`, `double`,
// `float`, and the sized aliases `i8..i64` / `u8..u64`. Implicit conversions
// are widening only (`char -> int`, narrower-int -> wider-int of the same
// signedness, `int -> double`, `float -> double`); everything else needs an
// explicit `expr to T`. Where an implicit widening is needed, sema splices an
// `ast::ImplicitConversionExpr` into the tree so codegen just emits it.

#include "jocky/sema/Sema.h"

#include "jocky/Support/Diagnostic.h"
#include "jocky/ast/AST.h"

#include <llvm/ADT/SmallVector.h>
#include <llvm/ADT/StringMap.h>
#include <llvm/ADT/StringSet.h>
#include <llvm/ADT/StringSwitch.h>
#include <llvm/ADT/Twine.h>

#include <algorithm>
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
    bool isExtern = false;
    bool isVarArg = false;
};

class Checker {
public:
    Checker(ast::Module &module, DiagnosticEngine &diags)
        : module_(module), diags_(diags) {}

    bool run() {
        for (ast::StructDecl *s : module_.structs) registerStruct(*s);
        for (ast::StructDecl *s : module_.structs) layoutStruct(*s);
        for (ast::ExternDecl *e : module_.externs) declareExtern(*e);
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

    static unsigned alignUp(unsigned n, unsigned a) {
        return a <= 1 ? n : (n + a - 1) / a * a;
    }

    // --- structs (L2.2) ----------------------------------------
    void registerStruct(const ast::StructDecl &s) {
        if (structs_.count(s.name)) {
            err(s.loc, llvm::Twine("struct '") + s.name +
                           "' is defined more than once");
            return;
        }
        auto si = std::make_shared<ast::StructInfo>();
        si->name = s.name;
        structs_[s.name] = std::move(si);
        structDecls_[s.name] = const_cast<ast::StructDecl *>(&s);
        structState_[s.name] = 0;
    }

    // Ensure `name`'s layout is computed; report a cycle if it is mid-layout.
    void ensureLaidOut(llvm::StringRef name, SourceLocation useLoc) {
        auto st = structState_.find(name);
        if (st == structState_.end()) return;  // not a struct / registration failed
        if (st->second == 2) return;
        if (st->second == 1) {
            err(useLoc, llvm::Twine("struct '") + name +
                            "' contains itself by value (use ptr<" + name +
                            "> for a self-reference)");
            return;
        }
        layoutStruct(*structDecls_[name]);
    }

    void layoutStruct(const ast::StructDecl &s) {
        auto st = structState_.find(s.name);
        if (st == structState_.end() || st->second != 0) return;
        st->second = 1;

        ast::StructInfo &si = *structs_[s.name];
        unsigned offset = 0, align = 1;
        llvm::StringSet<> seen;
        for (const ast::FieldDecl &f : s.fields) {
            if (!seen.insert(f.name).second) {
                err(f.loc, llvm::Twine("duplicate field '") + f.name +
                               "' in struct '" + s.name + "'");
                continue;
            }
            Type ft = resolveType(f.typeAnnotation, /*completeStructs=*/true);
            if (ft.isVoid()) {
                err(f.typeAnnotation->loc, "a struct field cannot have type "
                                           "'nothing'");
                ft = Type::error();
            }
            const unsigned fa = ft.isError() ? 1 : ft.alignOf();
            offset = alignUp(offset, fa);
            si.fields.push_back(ast::FieldInfo{f.name, ft, offset});
            if (!ft.isError())
                offset += static_cast<unsigned>(ft.byteSize());
            align = std::max(align, fa);
        }
        si.align = align;
        si.size = alignUp(offset, align);
        st->second = 2;
    }

    // type res
    Type resolveType(const ast::TypeExpr *te, bool completeStructs = true) {
        switch (te->form) {
        case ast::TypeExpr::Form::Name:
            break;
        case ast::TypeExpr::Form::Slice: {
            Type elem = resolveType(te->element);
            if (elem.isError()) return Type::error();
            if (elem.isVoid()) {
                err(te->loc, "a slice element cannot be 'nothing'");
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
                err(te->loc, "an array element cannot be 'nothing'");
                return Type::error();
            }
            if (!okN) {
                err(te->sizeExpr->loc,
                    "array length must be a constant non-negative integer");
                return Type::error();
            }
            return Type::array(elem, static_cast<unsigned>(n));
        }
        case ast::TypeExpr::Form::Pointer: {
            // A pointee never needs a complete layout: `ptr<S>` is 8 bytes even
            // while `S` is mid-layout (this is how a struct self-references).
            Type pointee = resolveType(te->element, /*completeStructs=*/false);
            if (pointee.isError()) return Type::error();
            if (pointee.isVoid()) {
                err(te->loc, "use 'rawptr', not 'ptr<nothing>'");
                return Type::error();
            }
            return Type::pointer(pointee);
        }
        }

        const Type t = llvm::StringSwitch<Type>(te->name)
                           .Case("nothing", Type::voidTy())
                           .Case("flag", Type::boolTy())
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
                           .Case("rawptr", Type::rawPtr())
                           .Default(Type::error());
        if (!t.isError()) return t;

        if (auto sit = structs_.find(te->name); sit != structs_.end()) {
            if (completeStructs) ensureLaidOut(te->name, te->loc);
            return Type::structType(sit->second);
        }

        err(te->loc, llvm::Twine("unknown type '") + te->name + "'");
        return Type::error();
    }

    // A minimal compile-time evaluator for an array length: integer literals,
    // `+ - * / %` over them, `sizeof(T)`, plus parenthesised / cast forms.
    // Enough for `char[4096]`, `int[N*2]`, `u8[sizeof(int)]`. Returns false if
    // `e` is not foldable or is negative.
    bool constUint(const ast::Expr &e, std::uint64_t &out) {
        switch (e.kind) {
        case ast::NodeKind::IntLiteralExpr: {
            const auto &n = static_cast<const ast::IntLiteralExpr &>(e);
            if (n.value < 0) return false;
            out = static_cast<std::uint64_t>(n.value);
            return true;
        }
        case ast::NodeKind::SizeofExpr: {
            const auto &s = static_cast<const ast::SizeofExpr &>(e);
            if (!s.typeArg) return false;  // sizeof(expr) is not folded here
            const Type m = resolveType(s.typeArg);
            if (m.isError() || m.byteSize() == 0) return false;
            out = m.byteSize();
            return true;
        }
        case ast::NodeKind::OffsetofExpr: {
            const auto &o = static_cast<const ast::OffsetofExpr &>(e);
            auto sit = structs_.find(o.structName);
            if (sit == structs_.end()) return false;
            ensureLaidOut(o.structName, o.loc);
            const ast::FieldInfo *f = sit->second->find(o.fieldName);
            if (!f) return false;
            out = f->offset;
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

    // What `expr as T` accepts: any scalar to any other scalar, any pointer to
    // any other pointer (`rawptr` <-> `ptr<T>`, `ptr<T>` <-> `ptr<U>`), and a
    // pointer to or from an integer (`addr as ptr<T>`, `p as u64`).
    static bool explicitlyConvertible(Type from, Type to) {
        if (from.isError() || to.isError()) return true;
        if (from.isPointer() && to.isPointer()) return true;
        if (from.isPointer() && to.isInteger()) return true;
        if (from.isInteger() && to.isPointer()) return true;
        // An array or slice `as` a pointer yields its base address, so a struct
        // can be overlaid on a byte buffer: `(buf as ptr<Header>).field` (L1.6).
        if ((from.isArray() || from.isSlice()) && to.isPointer()) return true;
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

        // `null` takes on whatever pointer type its context wants.
        if (slot->kind == ast::NodeKind::NullLiteralExpr && to.isPointer()) {
            slot->type = to;
            return true;
        }

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
                        "a parameter cannot have type 'nothing'");
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

    void declareExtern(ast::ExternDecl &e) {
        if (functions_.count(e.name)) {
            err(e.loc, llvm::Twine("'") + e.name + "' is declared more than once");
            return;
        }
        FnSig sig;
        sig.isExtern = true;
        sig.isVarArg = e.isVarArg;
        for (ast::Param &p : e.params) {
            if (!p.typeAnnotation) {
                err(p.loc,
                    llvm::Twine("parameter '") + p.name + "' needs a type");
                p.type = Type::error();
            } else {
                p.type = resolveType(p.typeAnnotation);
                if (p.type.isVoid()) {
                    err(p.typeAnnotation->loc,
                        "an extern parameter cannot have type 'nothing'");
                    p.type = Type::error();
                }
                if (p.type.isStruct()) {
                    err(p.typeAnnotation->loc,
                        llvm::Twine("pass a struct to an extern by pointer "
                                    "('ptr<") +
                            p.type.name() + ">'), not by value");
                    p.type = Type::error();
                }
            }
            sig.params.push_back(p.type);
        }
        e.resolvedReturn =
            e.returnType ? resolveType(e.returnType) : Type::intTy();
        if (e.resolvedReturn.isStruct()) {
            err(e.loc, "an extern cannot return a struct by value");
            e.resolvedReturn = Type::error();
        }
        sig.ret = e.resolvedReturn;
        functions_[e.name] = std::move(sig);
    }

    // pass 2: bodies
    void checkFunctionBody(ast::FunctionDecl &fn) {
        locals_.clear();
        loopDepth_ = 0;
        for (const ast::Param &p : fn.params) locals_[p.name] = p.type;
        currentReturn_ = fn.resolvedReturn;
        if (fn.body) checkBlock(*fn.body);
    }

    void checkImplicitMain() {
        locals_.clear();
        loopDepth_ = 0;
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
            ++loopDepth_;
            checkBlock(*w.body);
            --loopDepth_;
            return;
        }
        case ast::NodeKind::BreakStmt:
            if (loopDepth_ == 0) err(stmt.loc, "'stop' outside a loop");
            return;
        case ast::NodeKind::ContinueStmt:
            if (loopDepth_ == 0) err(stmt.loc, "'skip' outside a loop");
            return;
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
                err(v.typeAnnotation->loc,
                    "a variable cannot have type 'nothing'");
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
                        " (add an explicit `to " + ann.name() + "`)");
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
                    " (add an explicit `to " + targetT.name() + "`)");
    }

    // A storable location: a variable, an array/slice element, `*p`, or a struct
    // field (of a struct value or through a `ptr<S>`).
    static bool isLValue(const ast::Expr &e) {
        if (e.kind == ast::NodeKind::VarRefExpr ||
            e.kind == ast::NodeKind::IndexExpr ||
            e.kind == ast::NodeKind::DerefExpr)
            return true;
        if (e.kind == ast::NodeKind::MemberExpr) {
            const Type bt = static_cast<const ast::MemberExpr &>(e).base->type;
            return bt.isStruct() ||
                   (bt.isTypedPointer() && bt.pointee().isStruct());
        }
        return false;
    }

    void checkReturn(ast::ReturnStmt &r) {
        if (!r.value) return;  // bare `return;` -> the zero value / nothing

        const Type vt = checkExpr(*r.value);
        if (vt.isError()) return;

        if (currentReturn_.isVoid()) {
            err(r.value->loc,
                "returning a value from a function declared `-> nothing`");
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
        err(e.loc, llvm::Twine("condition must be a flag or an integer, not ") +
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
            if (u.op == ast::UnaryOp::BitNot) {
                if (!ot.isInteger()) {
                    err(u.loc, llvm::Twine("unary '~' needs an integer, not ") +
                                   ot.name());
                    return Type::error();
                }
                return ot;
            }
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
        case ast::NodeKind::NullLiteralExpr:
            return Type::rawPtr();  // adapts to any pointer type via coerce()
        case ast::NodeKind::AddrOfExpr:
            return checkAddrOf(static_cast<ast::AddrOfExpr &>(e));
        case ast::NodeKind::DerefExpr:
            return checkDeref(static_cast<ast::DerefExpr &>(e));
        case ast::NodeKind::SizeofExpr:
            return checkSizeof(static_cast<ast::SizeofExpr &>(e));
        case ast::NodeKind::OffsetofExpr:
            return checkOffsetof(static_cast<ast::OffsetofExpr &>(e));
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

        // A `ptr<S>` auto-dereferences for field access (the L1.6 overlay).
        Type recT = baseT;
        if (baseT.isTypedPointer() && baseT.pointee().isStruct())
            recT = baseT.pointee();

        if (recT.isStruct()) {
            const ast::FieldInfo *f = recT.structInfo().find(e.member);
            if (!f) {
                err(e.loc, llvm::Twine("struct '") + recT.name() +
                               "' has no field '" + e.member + "'");
                return Type::error();
            }
            return f->type;
        }

        if (e.member == "len") {
            if (baseT.isArray() || baseT.isSlice()) return Type::intTy();
            err(e.loc, llvm::Twine("'.len' needs an array or a slice, not ") +
                           baseT.name());
            return Type::error();
        }

        err(e.loc, llvm::Twine("type ") + baseT.name() + " has no member '" +
                       e.member + "'");
        return Type::error();
    }

    Type checkOffsetof(ast::OffsetofExpr &e) {
        auto sit = structs_.find(e.structName);
        if (sit == structs_.end()) {
            err(e.loc, llvm::Twine("unknown struct '") + e.structName + "'");
            return Type::error();
        }
        ensureLaidOut(e.structName, e.loc);
        const ast::FieldInfo *f = sit->second->find(e.fieldName);
        if (!f) {
            err(e.loc, llvm::Twine("struct '") + e.structName +
                           "' has no field '" + e.fieldName + "'");
            return Type::error();
        }
        e.resolvedOffset = f->offset;
        return Type::intTy();
    }

    Type checkAddrOf(ast::AddrOfExpr &e) {
        const Type ot = checkExpr(*e.operand);
        if (ot.isError()) return Type::error();
        if (!isLValue(*e.operand)) {
            err(e.loc, "'&' needs an addressable value (a variable, an array "
                       "element, or *p)");
            return Type::error();
        }
        return Type::pointer(ot);
    }

    static bool isBuiltinTypeName(llvm::StringRef n) {
        return llvm::StringSwitch<bool>(n)
            .Cases("nothing", "flag", "int", "char", true)
            .Cases("i8", "i16", "i32", "i64", true)
            .Cases("u8", "u16", "u32", "u64", true)
            .Cases("float", "double", "rawptr", true)
            .Default(false);
    }

    Type checkSizeof(ast::SizeofExpr &e) {
        if (e.typeArg) {
            // `sizeof(name)` is ambiguous: `name` may be a type or a variable.
            // Prefer a variable unless the name is a builtin type. (Array /
            // slice / pointer forms are unambiguously types.)
            if (e.typeArg->form == ast::TypeExpr::Form::Name &&
                !isBuiltinTypeName(e.typeArg->name)) {
                auto it = locals_.find(e.typeArg->name);
                if (it != locals_.end()) {
                    e.measured = it->second;
                    return e.measured.isError() ? Type::error() : Type::intTy();
                }
            }
            e.measured = resolveType(e.typeArg);
        } else {
            e.measured = checkExpr(*e.exprArg);
        }
        if (e.measured.isError()) return Type::error();
        if (e.measured.isVoid()) {
            err(e.loc, "sizeof needs a sized type, not 'nothing'");
            return Type::error();
        }
        return Type::intTy();  // a compile-time int
    }

    Type checkDeref(ast::DerefExpr &e) {
        const Type ot = checkExpr(*e.operand);
        if (ot.isError()) return Type::error();
        if (!ot.isPointer()) {
            err(e.loc, llvm::Twine("cannot dereference a value of type ") +
                           ot.name());
            return Type::error();
        }
        if (ot.isRawPointer()) {
            err(e.loc, "cannot dereference a rawptr (cast it to a ptr<T> first)");
            return Type::error();
        }
        return ot.pointee();
    }

    static bool isBitwise(ast::BinaryOp op) {
        return op == ast::BinaryOp::BitAnd || op == ast::BinaryOp::BitOr ||
               op == ast::BinaryOp::BitXor;
    }
    static bool isShift(ast::BinaryOp op) {
        return op == ast::BinaryOp::Shl || op == ast::BinaryOp::Shr;
    }

    // Operators with at least one pointer operand:
    //   ptr == / != ptr | null,  ptr </ <= / > / >= ptr  -> bool
    //   ptr + int,  int + ptr,  ptr - int                 -> the pointer type
    //   ptr<T> - ptr<T>  (or rawptr - rawptr)             -> int (element count)
    Type checkPointerBinary(ast::BinaryExpr &b, Type lt, Type rt) {
        if (b.lhs->kind == ast::NodeKind::NullLiteralExpr && rt.isPointer()) {
            b.lhs->type = rt;
            lt = rt;
        }
        if (b.rhs->kind == ast::NodeKind::NullLiteralExpr && lt.isPointer()) {
            b.rhs->type = lt;
            rt = lt;
        }

        // ptr +/- int  (int + ptr commutes for `+`). The offset keeps its own
        // integer type; codegen sign/zero-extends it to a machine word.
        if (b.op == ast::BinaryOp::Add || b.op == ast::BinaryOp::Sub) {
            const bool lPtr = lt.isPointer(), rPtr = rt.isPointer();
            if (lPtr && rt.isInteger()) {
                adaptIntLiteral(*b.rhs, Type::intTy());
                return lt;
            }
            if (b.op == ast::BinaryOp::Add && rPtr && lt.isInteger()) {
                adaptIntLiteral(*b.lhs, Type::intTy());
                return rt;
            }
            if (b.op == ast::BinaryOp::Sub && lPtr && rPtr) {
                if (lt != rt) {
                    err(b.loc, llvm::Twine("subtracting incompatible pointer "
                                           "types ") +
                                   lt.name() + " and " + rt.name());
                    return Type::error();
                }
                return Type::intTy();  // element (or byte, for rawptr) count
            }
            err(b.loc, llvm::Twine("operator '") + ast::binaryOpSymbol(b.op) +
                           "' cannot combine " + lt.name() + " and " + rt.name());
            return Type::error();
        }

        if (!lt.isPointer() || !rt.isPointer()) {
            err(b.loc, llvm::Twine("operator '") + ast::binaryOpSymbol(b.op) +
                           "' cannot combine " + lt.name() + " and " + rt.name());
            return Type::error();
        }
        if (!ast::isComparison(b.op)) {
            err(b.loc, llvm::Twine("operator '") + ast::binaryOpSymbol(b.op) +
                           "' is not defined on pointers");
            return Type::error();
        }
        if (lt != rt) {
            err(b.loc, llvm::Twine("comparing incompatible pointer types ") +
                           lt.name() + " and " + rt.name() +
                           " (add an explicit `to`)");
            return Type::error();
        }
        return Type::boolTy();
    }

    Type checkBinary(ast::BinaryExpr &b) {
        Type lt = checkExpr(*b.lhs);
        Type rt = checkExpr(*b.rhs);
        if (lt.isError() || rt.isError()) return Type::error();

        if (lt.isPointer() || rt.isPointer())
            return checkPointerBinary(b, lt, rt);

        // Shift: an integer value shifted by an integer count. The count keeps
        // its own type (codegen converts it to the value's type); result type is
        // the value's. `>>` is arithmetic for signed, logical for unsigned.
        if (isShift(b.op)) {
            if (!lt.isInteger() || !rt.isInteger()) {
                err(b.loc, llvm::Twine("operator '") + ast::binaryOpSymbol(b.op) +
                               "' needs integer operands, not " + lt.name() +
                               " and " + rt.name());
                return Type::error();
            }
            adaptIntLiteral(*b.rhs, lt);  // tidies a bare count literal
            return lt;
        }

        const bool wantInteger = isBitwise(b.op) || b.op == ast::BinaryOp::Mod;

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
                           rt.name() + " (add an explicit `to`)");
            return Type::error();
        }

        if (wantInteger && !common.isInteger()) {
            err(b.loc, llvm::Twine("operator '") + ast::binaryOpSymbol(b.op) +
                           "' needs integer operands");
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
        const bool countOk = sig.isVarArg
                                 ? c.args.size() >= sig.params.size()
                                 : c.args.size() == sig.params.size();
        if (!countOk) {
            err(c.loc, llvm::Twine("function '") + c.callee + "' expects " +
                           (sig.isVarArg ? "at least " : "") +
                           llvm::Twine(sig.params.size()) + " argument(s) but " +
                           llvm::Twine(c.args.size()) + " were given");
            for (ast::Expr *a : c.args) checkExpr(*a);
            return sig.ret;
        }

        for (std::size_t i = 0; i < c.args.size(); ++i) {
            const Type at = checkExpr(*c.args[i]);
            if (i >= sig.params.size()) continue;  // a varargs `...` argument
            const Type pt = sig.params[i];
            if (!at.isError() && !pt.isError() && !coerce(c.args[i], pt))
                err(c.args[i]->loc,
                    llvm::Twine("argument ") + llvm::Twine(i + 1) + " to '" +
                        c.callee + "' has type " + at.name() + " but " +
                        pt.name() + " was expected (add an explicit `to " +
                        pt.name() + "`)");
        }
        return sig.ret;
    }

    Type checkCast(ast::CastExpr &c) {
        const Type from = checkExpr(*c.operand);
        const Type to = resolveType(c.targetType);
        if (from.isError() || to.isError()) return to;

        if (to.isVoid()) {
            err(c.loc, "cannot cast to 'nothing'");
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
    int loopDepth_ = 0;  // reset per function; > 0 inside a while body

    // Struct declarations, resolved once up front. `structState_`: 0 pending,
    // 1 being laid out (a cycle if we see it again), 2 done.
    llvm::StringMap<std::shared_ptr<ast::StructInfo>> structs_;
    llvm::StringMap<ast::StructDecl *> structDecls_;
    llvm::StringMap<int> structState_;
};

}  // namespace

bool analyze(ast::Module &module, DiagnosticEngine &diags) {
    return Checker(module, diags).run();
}

}  // namespace jocky::sema
