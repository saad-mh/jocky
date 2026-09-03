// Driver implementation.
//
// The driver reads the input file once and then runs whichever pipeline the
// sub-command asks for. Stages are added here as they are implemented; right
// now `lex` and `parse` work and `build` is still a stub.

#include "jocky/driver/Driver.h"

#include "jocky/Support/Diagnostic.h"
#include "jocky/Support/StringEscape.h"
#include "jocky/ast/ASTPrinter.h"
#include "jocky/ast/AST.h"
#include "jocky/lexer/Lexer.h"
#include "jocky/lexer/Token.h"
#include "jocky/parser/Parser.h"

#include <llvm/Support/MemoryBuffer.h>
#include <llvm/Support/raw_ostream.h>

#include <memory>
#include <string>
#include <vector>

namespace jocky::driver {

namespace {

// Reads the whole input file. On failure prints a diagnostic-style message and
// returns nullptr.
std::unique_ptr<llvm::MemoryBuffer> readInput(const std::string &path) {
    llvm::ErrorOr<std::unique_ptr<llvm::MemoryBuffer>> bufOr =
        llvm::MemoryBuffer::getFile(path);
    if (!bufOr) {
        llvm::errs() << path << ":0:0: error: cannot open file: "
                     << bufOr.getError().message() << '\n';
        return nullptr;
    }
    return std::move(*bufOr);
}

// One line per token, for `jocky lex --dump-tokens`.
void printToken(llvm::raw_ostream &os, const Token &t) {
    os << t.location.line << ':' << t.location.column << ": "
       << tokenKindName(t.kind);
    if (t.kind != TokenKind::Eof) {
        os << " '" << t.spelling << '\'';
    }
    switch (t.kind) {
    case TokenKind::IntLiteral:
        os << " int=" << t.intValue;
        break;
    case TokenKind::StringLiteral:
        os << " str=" << encodeStringLiteral(t.stringValue);
        break;
    case TokenKind::Error:
        os << " (" << t.stringValue << ')';
        break;
    default:
        break;
    }
    os << '\n';
}

int runLex(const Options &options) {
    std::unique_ptr<llvm::MemoryBuffer> buffer = readInput(options.inputPath);
    if (!buffer) return 1;

    DiagnosticEngine diags(options.inputPath);
    Lexer lexer(buffer->getBuffer(), diags);
    const std::vector<Token> tokens = lexer.tokenize();

    if (options.dumpTokens) {
        for (const Token &t : tokens) printToken(llvm::outs(), t);
    }

    diags.printAll(llvm::errs());
    return diags.hasErrors() ? 1 : 0;
}

int runParse(const Options &options) {
    std::unique_ptr<llvm::MemoryBuffer> buffer = readInput(options.inputPath);
    if (!buffer) return 1;

    DiagnosticEngine diags(options.inputPath);

    Lexer lexer(buffer->getBuffer(), diags);
    const std::vector<Token> tokens = lexer.tokenize();
    if (diags.hasErrors()) {
        diags.printAll(llvm::errs());
        return 1;
    }

    Parser parser(tokens, diags);
    const std::unique_ptr<ast::Module> module = parser.parseModule();
    if (diags.hasErrors()) {
        diags.printAll(llvm::errs());
        return 1;
    }

    if (options.dumpAst) {
        ast::printAST(llvm::outs(), *module);
    }
    return 0;
}

}  // namespace

int Driver::run(const Options &options) {
    switch (options.command) {
    case Command::Lex:
        return runLex(options);

    case Command::Parse:
        return runParse(options);

    case Command::Build:
        llvm::errs() << "jocky: `build` is not implemented yet "
                        "(the compiler pipeline is still being built up)\n";
        return 1;

    case Command::None:
        llvm::errs() << "jocky: no command given (try `jocky --help`)\n";
        return 2;
    }

    return 2;  // unreachable
}

}  // namespace jocky::driver
