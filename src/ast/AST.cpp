#include "jocky/ast/AST.h"

namespace jocky::ast {

// Out-of-line so the Node vtable is emitted in exactly one translation unit.
Node::~Node() = default;

const char *unaryOpName(UnaryOp op) {
    switch (op) {
    case UnaryOp::Neg: return "Neg";
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
    case BinaryOp::Eq: return "Eq";
    case BinaryOp::Ne: return "Ne";
    case BinaryOp::Lt: return "Lt";
    case BinaryOp::Le: return "Le";
    case BinaryOp::Gt: return "Gt";
    case BinaryOp::Ge: return "Ge";
    }
    return "<unknown>";
}

}  // namespace jocky::ast
