// The lexer: source text in, a flat list of tokens out.
//
// It is hand-written (no generator) and deliberately simple. It never throws
// and never stops early: on a bad character or an unterminated string it
// reports an error to the DiagnosticEngine, emits an Error token, and carries
// on. Callers check diags.hasErrors() afterwards.

#ifndef JOCKY_LEXER_LEXER_H
#define JOCKY_LEXER_LEXER_H

#include "jocky/lexer/Token.h"

#include <cstddef>
#include <cstdint>
#include <vector>

#include <llvm/ADT/StringRef.h>

namespace jocky {

class DiagnosticEngine;

class Lexer {
public:
    Lexer(llvm::StringRef source, DiagnosticEngine &diags);

    // Lexes the entire input. The result always ends with exactly one Eof token.
    std::vector<Token> tokenize();

private:
    Token nextToken();

    Token lexNumber();
    Token lexString();
    Token lexIdentifierOrKeyword();
    void skipWhitespaceAndComments();

    // Character cursor helpers.
    bool atEnd() const { return offset_ >= source_.size(); }
    char peek(std::size_t ahead = 0) const;
    char advance();  // consumes one character, updating line/column

    // Builds a token spanning [startOffset, offset_) with the given kind and
    // start location.
    Token finish(TokenKind kind, std::size_t startOffset,
                 SourceLocation startLoc) const;

    llvm::StringRef source_;
    DiagnosticEngine &diags_;
    std::size_t offset_ = 0;
    std::uint32_t line_ = 1;
    std::uint32_t column_ = 1;
};

}  // namespace jocky

#endif  // JOCKY_LEXER_LEXER_H
