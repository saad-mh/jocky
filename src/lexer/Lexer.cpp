#include "jocky/lexer/Lexer.h"

#include "jocky/Support/Diagnostic.h"
#include "jocky/Support/StringEscape.h"

#include <llvm/ADT/StringSwitch.h>
#include <llvm/ADT/Twine.h>

#include <cstdint>
#include <limits>

namespace jocky {

namespace {

bool isDigit(char c) { return c >= '0' && c <= '9'; }

bool isIdentStart(char c) {
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '_';
}

bool isIdentContinue(char c) { return isIdentStart(c) || isDigit(c); }

}  // namespace

llvm::StringRef tokenKindName(TokenKind kind) {
    switch (kind) {
    case TokenKind::IntLiteral: return "IntLiteral";
    case TokenKind::StringLiteral: return "StringLiteral";
    case TokenKind::Identifier: return "Identifier";
    case TokenKind::KwFunc: return "KwFunc";
    case TokenKind::KwVar: return "KwVar";
    case TokenKind::KwIf: return "KwIf";
    case TokenKind::KwElse: return "KwElse";
    case TokenKind::KwWhile: return "KwWhile";
    case TokenKind::KwReturn: return "KwReturn";
    case TokenKind::LParen: return "LParen";
    case TokenKind::RParen: return "RParen";
    case TokenKind::LBrace: return "LBrace";
    case TokenKind::RBrace: return "RBrace";
    case TokenKind::Comma: return "Comma";
    case TokenKind::Semicolon: return "Semicolon";
    case TokenKind::Assign: return "Assign";
    case TokenKind::Plus: return "Plus";
    case TokenKind::Minus: return "Minus";
    case TokenKind::Star: return "Star";
    case TokenKind::Slash: return "Slash";
    case TokenKind::Percent: return "Percent";
    case TokenKind::EqEq: return "EqEq";
    case TokenKind::NotEq: return "NotEq";
    case TokenKind::Lt: return "Lt";
    case TokenKind::LtEq: return "LtEq";
    case TokenKind::Gt: return "Gt";
    case TokenKind::GtEq: return "GtEq";
    case TokenKind::Eof: return "Eof";
    case TokenKind::Error: return "Error";
    }
    return "<unknown>";
}

Lexer::Lexer(llvm::StringRef source, DiagnosticEngine &diags)
    : source_(source), diags_(diags) {}

char Lexer::peek(std::size_t ahead) const {
    const std::size_t i = offset_ + ahead;
    return i < source_.size() ? source_[i] : '\0';
}

char Lexer::advance() {
    if (atEnd()) return '\0';
    const char c = source_[offset_++];
    if (c == '\n') {
        ++line_;
        column_ = 1;
    } else {
        ++column_;
    }
    return c;
}

Token Lexer::finish(TokenKind kind, std::size_t startOffset,
                    SourceLocation startLoc) const {
    Token t;
    t.kind = kind;
    t.spelling = source_.substr(startOffset, offset_ - startOffset);
    t.location = startLoc;
    return t;
}

void Lexer::skipWhitespaceAndComments() {
    for (;;) {
        const char c = peek();
        if (c == ' ' || c == '\t' || c == '\r' || c == '\n') {
            advance();
            continue;
        }
        // Line comment: `//` to end of line.
        if (c == '/' && peek(1) == '/') {
            while (!atEnd() && peek() != '\n') advance();
            continue;
        }
        break;
    }
}

std::vector<Token> Lexer::tokenize() {
    std::vector<Token> tokens;
    for (;;) {
        Token t = nextToken();
        const bool isEof = t.kind == TokenKind::Eof;
        tokens.push_back(std::move(t));
        if (isEof) break;
    }
    return tokens;
}

Token Lexer::nextToken() {
    skipWhitespaceAndComments();

    const std::size_t start = offset_;
    const SourceLocation loc{line_, column_};

    if (atEnd()) {
        Token t;
        t.kind = TokenKind::Eof;
        t.location = loc;
        return t;
    }

    const char c = peek();

    if (isIdentStart(c)) return lexIdentifierOrKeyword();
    if (isDigit(c)) return lexNumber();
    if (c == '"') return lexString();

    // One- or two-character operators and punctuation.
    advance();
    switch (c) {
    case '(': return finish(TokenKind::LParen, start, loc);
    case ')': return finish(TokenKind::RParen, start, loc);
    case '{': return finish(TokenKind::LBrace, start, loc);
    case '}': return finish(TokenKind::RBrace, start, loc);
    case ',': return finish(TokenKind::Comma, start, loc);
    case ';': return finish(TokenKind::Semicolon, start, loc);
    case '+': return finish(TokenKind::Plus, start, loc);
    case '-': return finish(TokenKind::Minus, start, loc);
    case '*': return finish(TokenKind::Star, start, loc);
    case '/': return finish(TokenKind::Slash, start, loc);
    case '%': return finish(TokenKind::Percent, start, loc);
    case '=':
        if (peek() == '=') {
            advance();
            return finish(TokenKind::EqEq, start, loc);
        }
        return finish(TokenKind::Assign, start, loc);
    case '<':
        if (peek() == '=') {
            advance();
            return finish(TokenKind::LtEq, start, loc);
        }
        return finish(TokenKind::Lt, start, loc);
    case '>':
        if (peek() == '=') {
            advance();
            return finish(TokenKind::GtEq, start, loc);
        }
        return finish(TokenKind::Gt, start, loc);
    case '!':
        if (peek() == '=') {
            advance();
            return finish(TokenKind::NotEq, start, loc);
        }
        diags_.error(loc,
                     "unexpected '!' (JOCKY v0 has no logical-not operator; "
                     "did you mean '!='?)");
        {
            Token t = finish(TokenKind::Error, start, loc);
            t.stringValue = "unexpected '!'";
            return t;
        }
    default: {
        diags_.error(loc, llvm::Twine("unexpected character '") +
                              source_.substr(start, 1) + "'");
        Token t = finish(TokenKind::Error, start, loc);
        t.stringValue = "unexpected character";
        return t;
    }
    }
}

Token Lexer::lexNumber() {
    const std::size_t start = offset_;
    const SourceLocation loc{line_, column_};

    while (isDigit(peek())) advance();

    Token t = finish(TokenKind::IntLiteral, start, loc);

    // Parse the digits. StringRef::getAsInteger returns true on failure.
    std::uint64_t value = 0;
    const auto maxSigned =
        static_cast<std::uint64_t>(std::numeric_limits<std::int64_t>::max());
    if (t.spelling.getAsInteger(10, value) || value > maxSigned) {
        diags_.error(loc, llvm::Twine("integer literal '") + t.spelling +
                              "' does not fit in a 64-bit signed integer");
        t.kind = TokenKind::Error;
        t.stringValue = "integer literal out of range";
        return t;
    }
    t.intValue = static_cast<std::int64_t>(value);
    return t;
}

Token Lexer::lexString() {
    const std::size_t start = offset_;
    const SourceLocation loc{line_, column_};

    advance();  // opening quote
    const std::size_t bodyStart = offset_;

    // A string literal stays on one line. A backslash escapes the next
    // character (so \" does not end the string).
    while (!atEnd() && peek() != '"' && peek() != '\n') {
        if (peek() == '\\') {
            advance();
            if (!atEnd() && peek() != '\n') advance();
        } else {
            advance();
        }
    }

    if (atEnd() || peek() == '\n') {
        diags_.error(loc, "unterminated string literal");
        Token t = finish(TokenKind::Error, start, loc);
        t.stringValue = "unterminated string literal";
        return t;
    }

    const llvm::StringRef body = source_.substr(bodyStart, offset_ - bodyStart);
    advance();  // closing quote

    Token t = finish(TokenKind::StringLiteral, start, loc);

    std::string decoded;
    std::size_t errorOffset = 0;
    if (!decodeStringEscapes(body, decoded, &errorOffset)) {
        diags_.error(loc, "invalid escape sequence in string literal "
                          "(JOCKY v0 allows \\n \\t \\r \\\\ \\\" \\0)");
        t.kind = TokenKind::Error;
        t.stringValue = "invalid escape sequence";
        return t;
    }
    t.stringValue = std::move(decoded);
    return t;
}

Token Lexer::lexIdentifierOrKeyword() {
    const std::size_t start = offset_;
    const SourceLocation loc{line_, column_};

    while (isIdentContinue(peek())) advance();

    Token t = finish(TokenKind::Identifier, start, loc);
    t.kind = llvm::StringSwitch<TokenKind>(t.spelling)
                 .Case("func", TokenKind::KwFunc)
                 .Case("var", TokenKind::KwVar)
                 .Case("if", TokenKind::KwIf)
                 .Case("else", TokenKind::KwElse)
                 .Case("while", TokenKind::KwWhile)
                 .Case("return", TokenKind::KwReturn)
                 .Default(TokenKind::Identifier);
    return t;
}

}  // namespace jocky
