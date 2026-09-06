// The type of a JOCKY value.
//
// v0 had exactly one type (a 64-bit signed integer). The L0 milestone replaces
// that with a small static type system; this header is its core. A `Type` is a
// small value - copy it freely, compare it with `==`. The semantic-analysis
// stage (src/sema/) computes a `Type` for every expression and stores it on the
// node; codegen then lowers an already-typed tree.
//
// Scalar kinds plus the two aggregate forms L0.6 needs: a fixed array `T[N]`
// and a borrowed slice `T[]` (a `{ base, len }` pair). Pointer and struct types
// arrive in later milestones (L1/L2); the `kind` enum leaves room.

#ifndef JOCKY_AST_TYPE_H
#define JOCKY_AST_TYPE_H

#include <memory>
#include <string>

namespace jocky::ast {

enum class TypeKind {
    Error,  // stand-in after a type error; suppresses cascading diagnostics
    Void,   // no value (a `-> void` function's result)
    Bool,   // true / false
    Int,    // integer; see `bits` and `isSigned`
    Float,  // IEEE-754; `bits` is 32 (float) or 64 (double)
    Array,   // T[N] - contiguous storage; `element` is T, `length` is N
    Slice,   // T[]  - a borrowed { base, len } view; `element` is T
    Pointer, // ptr<T> (`element` is T) or rawptr (`element` is void)
};

struct Type {
    TypeKind kind = TypeKind::Error;
    unsigned bits = 0;      // Int: 8/16/32/64.  Float: 32/64.  Otherwise 0.
    bool isSigned = false;  // Int only.
    unsigned length = 0;    // Array only: the element count.
    std::shared_ptr<Type> element;  // Array / Slice: the element type.

    // --- factories ---------------------------------------------------
    static Type error() { return makeScalar(TypeKind::Error, 0, false); }
    static Type voidTy() { return makeScalar(TypeKind::Void, 0, false); }
    static Type boolTy() { return makeScalar(TypeKind::Bool, 0, false); }
    static Type integer(unsigned b, bool sign) {
        return makeScalar(TypeKind::Int, b, sign);
    }
    static Type f32() { return makeScalar(TypeKind::Float, 32, false); }
    static Type f64() { return makeScalar(TypeKind::Float, 64, false); }

    // `int` / `i64` and `char` / `u8` are spelling synonyms, not distinct types.
    static Type intTy() { return integer(64, true); }
    static Type charTy() { return integer(8, false); }

    static Type array(Type elem, unsigned n) {
        Type t;
        t.kind = TypeKind::Array;
        t.length = n;
        t.element = std::make_shared<Type>(std::move(elem));
        return t;
    }
    static Type slice(Type elem) {
        Type t;
        t.kind = TypeKind::Slice;
        t.element = std::make_shared<Type>(std::move(elem));
        return t;
    }
    static Type pointer(Type pointee) {
        Type t;
        t.kind = TypeKind::Pointer;
        t.element = std::make_shared<Type>(std::move(pointee));
        return t;
    }
    static Type rawPtr() { return pointer(voidTy()); }

    // --- queries ---------------------------------------------------
    bool isError() const { return kind == TypeKind::Error; }
    bool isVoid() const { return kind == TypeKind::Void; }
    bool isBool() const { return kind == TypeKind::Bool; }
    bool isInteger() const { return kind == TypeKind::Int; }
    bool isFloat() const { return kind == TypeKind::Float; }
    bool isNumeric() const { return isInteger() || isFloat(); }
    bool isArray() const { return kind == TypeKind::Array; }
    bool isSlice() const { return kind == TypeKind::Slice; }
    bool isPointer() const { return kind == TypeKind::Pointer; }
    bool isRawPointer() const { return isPointer() && element->isVoid(); }
    bool isTypedPointer() const { return isPointer() && !element->isVoid(); }
    bool isScalar() const { return isBool() || isNumeric(); }

    const Type &elem() const { return *element; }     // Array / Slice
    const Type &pointee() const { return *element; }  // Pointer

    // Size in bytes, C layout. 0 for `void` / an error. Scalar elements need no
    // padding, so an array is just `length * element size`; a slice is a
    // { ptr, i64 } pair. (Struct sizes arrive with struct types in L2.)
    unsigned long long byteSize() const {
        switch (kind) {
        case TypeKind::Bool: return 1;
        case TypeKind::Int:
        case TypeKind::Float: return bits / 8;
        case TypeKind::Pointer: return 8;
        case TypeKind::Slice: return 16;
        case TypeKind::Array: return length * element->byteSize();
        default: return 0;
        }
    }

    bool operator==(const Type &o) const {
        if (kind != o.kind || bits != o.bits || isSigned != o.isSigned ||
            length != o.length)
            return false;
        if (element || o.element) {
            if (!element || !o.element) return false;
            return *element == *o.element;
        }
        return true;
    }
    bool operator!=(const Type &o) const { return !(*this == o); }

    // A human-readable name for diagnostics and the AST dump: "int", "char",
    // "u32", "bool", "double", "void", "char[16]", "int[]", "<error>".
    std::string name() const;

private:
    static Type makeScalar(TypeKind k, unsigned b, bool sign) {
        Type t;
        t.kind = k;
        t.bits = b;
        t.isSigned = sign;
        return t;
    }
};

}  // namespace jocky::ast

#endif  // JOCKY_AST_TYPE_H
