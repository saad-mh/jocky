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
    }
    return "<error>";
}

}  // namespace jocky::ast
