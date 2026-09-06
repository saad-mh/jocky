#include "jocky/ast/Type.h"

namespace jocky::ast {

std::string Type::name() const {
    switch (kind) {
    case TypeKind::Error:
        return "<error>";
    case TypeKind::Void:
        return "void";
    case TypeKind::Bool:
        return "bool";
    case TypeKind::Int:
        // The two headline spellings win; the rest are the sized names.
        if (bits == 64 && isSigned) return "int";
        if (bits == 8 && !isSigned) return "char";
        return (isSigned ? "i" : "u") + std::to_string(bits);
    case TypeKind::Float:
        return bits == 32 ? "float" : "double";
    case TypeKind::Array:
        return element->name() + "[" + std::to_string(length) + "]";
    case TypeKind::Slice:
        return element->name() + "[]";
    case TypeKind::Pointer:
        return element->isVoid() ? "rawptr" : "ptr<" + element->name() + ">";
    case TypeKind::Struct:
        return record ? record->name : "<struct>";
    }
    return "<error>";
}

unsigned long long Type::byteSize() const {
    switch (kind) {
    case TypeKind::Bool:
        return 1;
    case TypeKind::Int:
    case TypeKind::Float:
        return bits / 8;
    case TypeKind::Pointer:
        return 8;
    case TypeKind::Slice:
        return 16;
    case TypeKind::Array:
        return length * element->byteSize();
    case TypeKind::Struct:
        return record ? record->size : 0;
    default:
        return 0;  // Void, Error
    }
}

unsigned Type::alignOf() const {
    switch (kind) {
    case TypeKind::Bool:
        return 1;
    case TypeKind::Int:
    case TypeKind::Float:
        return bits / 8;
    case TypeKind::Pointer:
    case TypeKind::Slice:
        return 8;
    case TypeKind::Array:
        return element->alignOf();
    case TypeKind::Struct:
        return record ? record->align : 1;
    default:
        return 1;
    }
}

}  // namespace jocky::ast
