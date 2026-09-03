// The tokens the lexer produces.

#ifndef JOCKY_LEXER_TOKEN_H
#define JOCKY_LEXER_TOKEN_H

#include "jocky/Support/SourceLocation.h"

#include <cstdint>
#include <string>

#include <llvm/ADT/StringRef.h>

namespace jocky {

enum class TokenKind {
    // Literals and names.
    IntLiteral,     // 123        (value in Token::intValue)
    StringLiteral,  // "a\nb"     (decoded bytes in Token::stringValue)
    Identifier,     // foo, print

    // Keywords. Note: `print` is NOT a keyword - it lexes as an Identifier and
    // is recognized as a builtin later, in codegen.
    KwFunc,
    KwVar,
    KwIf,
    KwElse,
    KwWhile,
    KwReturn,

    // Punctuation.
    LParen,     // (
    RParen,     // )
    LBrace,     // {
    RBrace,     // }
    Comma,      // ,
    Semicolon,  // ;

    // Operators.
    Assign,   // =
    Plus,     // +
    Minus,    // -
    Star,     // *
    Slash,    // /
    Percent,  // %
    EqEq,     // ==
    NotEq,    // !=
    Lt,       // <
    LtEq,     // <=
    Gt,       // >
    GtEq,     // >=

    Eof,    // end of input; always the last token
    Error,  // a lexing failure; Token::stringValue holds a short reason
};

struct Token {
    TokenKind kind = TokenKind::Eof;

    // The exact source text this token came from (a view into the source
    // buffer). Empty for Eof.
    llvm::StringRef spelling;

    SourceLocation location;

    // IntLiteral only: the parsed value.
    std::int64_t intValue = 0;

    // StringLiteral: the decoded bytes (escapes already resolved).
    // Error:         a short human-readable reason.
    std::string stringValue;
};

// The name of a token kind, e.g. "KwFunc" or "Plus". Used by `jocky lex
// --dump-tokens` and by tests.
llvm::StringRef tokenKindName(TokenKind kind);

}  // namespace jocky

#endif  // JOCKY_LEXER_TOKEN_H
