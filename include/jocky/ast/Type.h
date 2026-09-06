// The type of a JOCKY value.
//
// v0 had exactly one type (a 64-bit signed integer). The L0 milestone replaces
// that with a small static type system; this header is its core. A `Type` is a
// small value - copy it freely, compare it with `==`. The semantic-analysis
// stage (src/sema/) computes a `Type` for every expression and stores it on the
// node; codegen then lowers an already-typed tree.
//
// Only the kinds L0 needs today are here. Pointer, array, slice, and struct
// types arrive in later milestones (L1/L2); the `kind` enum leaves room.

#ifndef JOCKY_AST_TYPE_H
#define JOCKY_AST_TYPE_H

#include <string>

namespace jocky::ast {

enum class TypeKind {
    Error,  // stand-in after a type error; suppresses cascading diagnostics
    Void,   // no value (a `-> void` function's result)
    Bool,   // true / false
    Int,    // integer; see `bits` and `isSigned`
    Float,  // IEEE-754; `bits` is 32 (float) or 64 (double)
};

struct Type {
    TypeKind kind = TypeKind::Error;
    unsigned bits = 0;      // Int: 8/16/32/64.  Float: 32/64.  Otherwise 0.
    bool isSigned = false;  // Int only.

    // --- factories ---------------------------------------------------
    static Type error() { return {TypeKind::Error, 0, false}; }
    static Type voidTy() { return {TypeKind::Void, 0, false}; }
    static Type boolTy() { return {TypeKind::Bool, 0, false}; }
    static Type integer(unsigned b, bool sign) { return {TypeKind::Int, b, sign}; }
    static Type f32() { return {TypeKind::Float, 32, false}; }
    static Type f64() { return {TypeKind::Float, 64, false}; }

    // `int` / `i64` and `char` / `u8` are spelling synonyms, not distinct types.
    static Type intTy() { return integer(64, true); }
    static Type charTy() { return integer(8, false); }

    // --- queries ---------------------------------------------------
    bool isError() const { return kind == TypeKind::Error; }
    bool isVoid() const { return kind == TypeKind::Void; }
    bool isBool() const { return kind == TypeKind::Bool; }
    bool isInteger() const { return kind == TypeKind::Int; }
    bool isFloat() const { return kind == TypeKind::Float; }
    bool isNumeric() const { return isInteger() || isFloat(); }

    bool operator==(const Type &o) const {
        return kind == o.kind && bits == o.bits && isSigned == o.isSigned;
    }
    bool operator!=(const Type &o) const { return !(*this == o); }

    // A human-readable name for diagnostics and the AST dump: "int", "char",
    // "u32", "bool", "double", "void", "<error>".
    std::string name() const;
};

}  // namespace jocky::ast

#endif  // JOCKY_AST_TYPE_H
