#include "jocky/Support/Diagnostic.h"

#include <llvm/ADT/Twine.h>
#include <llvm/Support/raw_ostream.h>

#include <utility>

namespace jocky {

DiagnosticEngine::DiagnosticEngine(std::string filename)
    : filename_(std::move(filename)) {}

void DiagnosticEngine::error(SourceLocation loc, const llvm::Twine &message) {
    diagnostics_.push_back(Diagnostic{Severity::Error, loc, message.str()});
    ++errorCount_;
}

void DiagnosticEngine::printAll(llvm::raw_ostream &os) const {
    for (const Diagnostic &d : diagnostics_) {
        os << filename_ << ':' << d.location.line << ':' << d.location.column
           << ": error: " << d.message << '\n';
    }
}

}  // namespace jocky
