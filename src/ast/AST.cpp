#include "jocky/ast/AST.h"

namespace jocky::ast {

// Out-of-line so the Node vtable is emitted in exactly one translation unit.
Node::~Node() = default;

const char *unaryOpName(UnaryOp op) {
    switch (op) {
    case UnaryOp::Neg: return "Neg";
    case UnaryOp::BitNot: return "BitNot";
    }
    return "<unknown>";
}

const char *binaryOpName(BinaryOp op) {
    switch (op) {
    case BinaryOp::Add: return "Add";
    case BinaryOp::Sub: return "Sub";
    case BinaryOp::Mul: return "Mul";
    case BinaryOp::Div: return "Div";
    case BinaryOp::Mod: return "Mod";
    case BinaryOp::BitAnd: return "BitAnd";
    case BinaryOp::BitOr: return "BitOr";
    case BinaryOp::BitXor: return "BitXor";
    case BinaryOp::Shl: return "Shl";
    case BinaryOp::Shr: return "Shr";
    case BinaryOp::Eq: return "Eq";
    case BinaryOp::Ne: return "Ne";
    case BinaryOp::Lt: return "Lt";
    case BinaryOp::Le: return "Le";
    case BinaryOp::Gt: return "Gt";
    case BinaryOp::Ge: return "Ge";
    }
    return "<unknown>";
}

const char *binaryOpSymbol(BinaryOp op) {
    switch (op) {
    case BinaryOp::Add: return "+";
    case BinaryOp::Sub: return "-";
    case BinaryOp::Mul: return "*";
    case BinaryOp::Div: return "/";
    case BinaryOp::Mod: return "%";
    case BinaryOp::BitAnd: return "&";
    case BinaryOp::BitOr: return "|";
    case BinaryOp::BitXor: return "^";
    case BinaryOp::Shl: return "<<";
    case BinaryOp::Shr: return ">>";
    case BinaryOp::Eq: return "==";
    case BinaryOp::Ne: return "!=";
    case BinaryOp::Lt: return "<";
    case BinaryOp::Le: return "<=";
    case BinaryOp::Gt: return ">";
    case BinaryOp::Ge: return ">=";
    }
    return "?";
}

bool isComparison(BinaryOp op) {
    switch (op) {
    case BinaryOp::Eq:
    case BinaryOp::Ne:
    case BinaryOp::Lt:
    case BinaryOp::Le:
    case BinaryOp::Gt:
    case BinaryOp::Ge:
        return true;
    default:
        return false;
    }
}

}  // namespace jocky::ast
