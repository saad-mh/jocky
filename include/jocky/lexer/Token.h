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
    IntLiteral,     // 123, 0x2A, 42u32   (value in Token::intValue; see the
                    //                     int* suffix fields for a type suffix)
    FloatLiteral,   // 1.0, .5, 2.5e-3, 3.14f  (value in Token::floatValue;
                    //                          Token::floatIsF32 for the `f` form)
    CharLiteral,    // 'A', '\n'          (byte value in Token::intValue)
    StringLiteral,  // "a\nb"             (decoded bytes in Token::stringValue)
    Identifier,     // foo, print, int, u32   (type names are ordinary identifiers)

    // Keywords. Note: `print` is NOT a keyword - it lexes as an Identifier and
    // is recognized as a builtin later. Type names (`int`, `char`, `u32`, ...)
    // are likewise ordinary identifiers, resolved in type position by sema.
    KwFunc,
    KwVar,
    KwIf,
    KwElse,
    KwWhile,
    KwReturn,
    KwAs,     // the `expr as Type` cast operator
    KwTrue,
    KwFalse,

    // Punctuation.
    LParen,     // (
    RParen,     // )
    LBrace,     // {
    RBrace,     // }
    Comma,      // ,
    Colon,      // :
    Arrow,      // ->
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

    // IntLiteral / CharLiteral: the parsed value (a CharLiteral's byte is 0-255).
    std::int64_t intValue = 0;

    // FloatLiteral: the parsed value.
    double floatValue = 0.0;
    bool floatIsF32 = false;  // FloatLiteral had an `f` suffix -> `float`, not `double`

    // IntLiteral: an explicit type suffix like `u32` / `i8`. `intSuffixBits == 0`
    // means "no suffix" (a bare literal, which defaults to `int`).
    unsigned intSuffixBits = 0;      // 8 / 16 / 32 / 64
    bool intSuffixSigned = true;     // `i*` -> true, `u*` -> false

    // StringLiteral: the decoded bytes (escapes already resolved).
    // Error:         a short human-readable reason.
    std::string stringValue;
};

// The name of a token kind, e.g. "KwFunc" or "Plus". Used by `jocky lex
// --dump-tokens` and by tests.
llvm::StringRef tokenKindName(TokenKind kind);

}  // namespace jocky

#endif  // JOCKY_LEXER_TOKEN_H
