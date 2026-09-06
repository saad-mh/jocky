// Error reporting shared by every compiler stage.
//
// A stage does not stop at the first problem: it reports each one to a
// DiagnosticEngine and keeps going where it can. The driver checks
// hasErrors() after the stage and stops the pipeline if anything went wrong.

#ifndef JOCKY_SUPPORT_DIAGNOSTIC_H
#define JOCKY_SUPPORT_DIAGNOSTIC_H

#include "jocky/Support/SourceLocation.h"

#include <cstddef>
#include <string>
#include <vector>

namespace llvm {
class raw_ostream;
class Twine;
}  // namespace llvm

namespace jocky {

// v0 only ever reports errors. Warning / Note can be added later without
// changing callers.
enum class Severity {
    Error,
};

struct Diagnostic {
    Severity severity = Severity::Error;
    SourceLocation location;
    std::string message;
};

class DiagnosticEngine {
public:
    // `filename` is used only to prefix printed messages.
    explicit DiagnosticEngine(std::string filename);

    // Records an error at `loc`. `message` is anything llvm::Twine accepts
    // (a string, a StringRef, "a " + Twine(n) + " b", ...).
    void error(SourceLocation loc, const llvm::Twine &message);

    bool hasErrors() const { return errorCount_ > 0; }
    std::size_t errorCount() const { return errorCount_; }
    const std::vector<Diagnostic> &diagnostics() const { return diagnostics_; }

    // Speculative parsing support: `mark()` records the current count; `rewind()`
    // drops every diagnostic recorded since a mark. Used when the parser tries
    // one interpretation, fails, and falls back to another (e.g. `sizeof(T)` vs
    // `sizeof(expr)`).
    std::size_t mark() const { return diagnostics_.size(); }
    void rewind(std::size_t m);

    // Prints every recorded diagnostic, in report order, as:
    //     <filename>:<line>:<column>: error: <message>
    void printAll(llvm::raw_ostream &os) const;

private:
    std::string filename_;
    std::vector<Diagnostic> diagnostics_;
    std::size_t errorCount_ = 0;
};

}  // namespace jocky

#endif  // JOCKY_SUPPORT_DIAGNOSTIC_H
