// Semantic analysis: the stage between the parser and codegen.
//
// The parser guarantees the program is well-formed *syntactically*. Sema is
// where the rest of the front-end's checking lives: every name resolves, every
// call matches a signature, and (from the L0 milestone on) every expression has
// a type that its context accepts. It walks the AST the parser built, reports
// problems through the DiagnosticEngine, and - once types arrive - annotates
// each expression node with its resolved `ast::Type`.
//
// Codegen runs only if `analyze` returned true, and then lowers a tree it can
// trust: it does no name lookup or argument-count checking of its own.

#ifndef JOCKY_SEMA_SEMA_H
#define JOCKY_SEMA_SEMA_H

namespace jocky {

class DiagnosticEngine;

namespace ast {
struct Module;
}

namespace sema {

// Checks `module` in place (later milestones annotate its expression nodes with
// resolved types). Returns true when nothing was reported. Diagnostics go to
// `diags`; the caller prints them and stops the pipeline on failure.
bool analyze(ast::Module &module, DiagnosticEngine &diags);

}  // namespace sema
}  // namespace jocky

#endif  // JOCKY_SEMA_SEMA_H
