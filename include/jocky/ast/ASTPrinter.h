// Prints an AST as an indented S-expression, for `jocky parse --dump-ast` and
// for parser tests. The format is meant to be read by people and matched by
// FileCheck; it is not a serialization format and may change.

#ifndef JOCKY_AST_ASTPRINTER_H
#define JOCKY_AST_ASTPRINTER_H

namespace llvm {
class raw_ostream;
}

namespace jocky::ast {

struct Module;

void printAST(llvm::raw_ostream &os, const Module &module);

}  // namespace jocky::ast

#endif  // JOCKY_AST_ASTPRINTER_H
