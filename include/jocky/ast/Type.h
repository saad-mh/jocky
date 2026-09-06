// The type of a JOCKY value.
//
// A `Type` is a small value - copy it freely, compare it with `==`. Compound
// types (array, slice, pointer, struct) hang their element / field types off a
// shared_ptr so `Type` stays copyable. Sema computes a `Type` for every
// expression and stores it on the node; codegen lowers an already-typed tree.

#ifndef JOCKY_AST_TYPE_H
#define JOCKY_AST_TYPE_H

#include <memory>
#include <string>
#include <vector>

#include <llvm/ADT/StringRef.h>

namespace jocky::ast {

struct StructInfo;  // defined at the bottom of this header

enum class TypeKind {
    Error,   // stand-in after a type error; suppresses cascading diagnostics
    Void,    // no value (a `-> void` function's result)
    Bool,    // true / false
    Int,     // integer; see `bits` and `isSigned`
    Float,   // IEEE-754; `bits` is 32 (float) or 64 (double)
    Array,   // T[N] - contiguous storage; `element` is T, `length` is N
    Slice,   // T[]  - a borrowed { base, len } view; `element` is T
    Pointer, // ptr<T> (`element` is T) or rawptr (`element` is void)
    Struct,  // a declared `struct` with C layout; see `record`
};

struct Type {
    TypeKind kind = TypeKind::Error;
    unsigned bits = 0;      // Int: 8/16/32/64.  Float: 32/64.  Otherwise 0.
    bool isSigned = false;  // Int only.
    unsigned length = 0;    // Array only: the element count.
    std::shared_ptr<Type> element;              // Array / Slice / Pointer
    std::shared_ptr<const StructInfo> record;   // Struct

    // --- factories ---------------------------------------------------
    static Type error() { return makeScalar(TypeKind::Error, 0, false); }
    static Type voidTy() { return makeScalar(TypeKind::Void, 0, false); }
    static Type boolTy() { return makeScalar(TypeKind::Bool, 0, false); }
    static Type integer(unsigned b, bool sign) {
        return makeScalar(TypeKind::Int, b, sign);
    }
    static Type f32() { return makeScalar(TypeKind::Float, 32, false); }
    static Type f64() { return makeScalar(TypeKind::Float, 64, false); }
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
    static Type structType(std::shared_ptr<const StructInfo> si) {
        Type t;
        t.kind = TypeKind::Struct;
        t.record = std::move(si);
        return t;
    }

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
    bool isStruct() const { return kind == TypeKind::Struct; }
    bool isScalar() const { return isBool() || isNumeric(); }

    const Type &elem() const { return *element; }     // Array / Slice
    const Type &pointee() const { return *element; }  // Pointer
    const StructInfo &structInfo() const { return *record; }  // Struct

    // C layout, in bytes / bytes. `alignOf` of `void` / error is 1, `byteSize`
    // 0. Out-of-line because the Struct cases need a complete StructInfo.
    unsigned long long byteSize() const;
    unsigned alignOf() const;

    bool operator==(const Type &o) const {
        if (kind != o.kind || bits != o.bits || isSigned != o.isSigned ||
            length != o.length)
            return false;
        if (kind == TypeKind::Struct) return record.get() == o.record.get();
        if (element || o.element) {
            if (!element || !o.element) return false;
            return *element == *o.element;
        }
        return true;
    }
    bool operator!=(const Type &o) const { return !(*this == o); }

    // A human-readable name for diagnostics and the AST dump: "int", "char",
    // "u32", "double", "char[16]", "int[]", "ptr<int>", "rawptr", "MyStruct".
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

// One field of a struct, after sema has resolved its type and C offset.
struct FieldInfo {
    std::string name;
    Type type;
    unsigned offset = 0;
};

// A declared struct's layout. Built once by sema and shared (nominal typing:
// two `StructInfo`s are the same type only if they are the same object).
struct StructInfo {
    std::string name;
    std::vector<FieldInfo> fields;
    unsigned size = 0;   // padded to `align`
    unsigned align = 1;

    const FieldInfo *find(llvm::StringRef fieldName) const {
        for (const FieldInfo &f : fields)
            if (f.name == fieldName) return &f;
        return nullptr;
    }
};

}  // namespace jocky::ast

#endif  // JOCKY_AST_TYPE_H
