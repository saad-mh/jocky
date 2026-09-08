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

bool isHexDigit(char c) {
    return isDigit(c) || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
}

bool isIdentStart(char c) {
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '_';
}

bool isIdentContinue(char c) { return isIdentStart(c) || isDigit(c); }

}  // namespace

llvm::StringRef tokenKindName(TokenKind kind) {
    switch (kind) {
    case TokenKind::IntLiteral: return "IntLiteral";
    case TokenKind::FloatLiteral: return "FloatLiteral";
    case TokenKind::CharLiteral: return "CharLiteral";
    case TokenKind::StringLiteral: return "StringLiteral";
    case TokenKind::Identifier: return "Identifier";
    case TokenKind::KwFunc: return "KwFunc";
    case TokenKind::KwLet: return "KwLet";
    case TokenKind::KwCheck: return "KwCheck";
    case TokenKind::KwElse: return "KwElse";
    case TokenKind::KwOtherwise: return "KwOtherwise";
    case TokenKind::KwWhile: return "KwWhile";
    case TokenKind::KwReturn: return "KwReturn";
    case TokenKind::KwStop: return "KwStop";
    case TokenKind::KwSkip: return "KwSkip";
    case TokenKind::KwStruct: return "KwStruct";
    case TokenKind::KwExtern: return "KwExtern";
    case TokenKind::KwTo: return "KwTo";
    case TokenKind::KwYes: return "KwYes";
    case TokenKind::KwNo: return "KwNo";
    case TokenKind::KwNone: return "KwNone";
    case TokenKind::KwSizeof: return "KwSizeof";
    case TokenKind::KwOffsetof: return "KwOffsetof";
    case TokenKind::LParen: return "LParen";
    case TokenKind::RParen: return "RParen";
    case TokenKind::LBrace: return "LBrace";
    case TokenKind::RBrace: return "RBrace";
    case TokenKind::LBracket: return "LBracket";
    case TokenKind::RBracket: return "RBracket";
    case TokenKind::Dot: return "Dot";
    case TokenKind::Comma: return "Comma";
    case TokenKind::Colon: return "Colon";
    case TokenKind::Arrow: return "Arrow";
    case TokenKind::Semicolon: return "Semicolon";
    case TokenKind::Assign: return "Assign";
    case TokenKind::Plus: return "Plus";
    case TokenKind::Minus: return "Minus";
    case TokenKind::Star: return "Star";
    case TokenKind::Slash: return "Slash";
    case TokenKind::Percent: return "Percent";
    case TokenKind::Amp: return "Amp";
    case TokenKind::Pipe: return "Pipe";
    case TokenKind::Caret: return "Caret";
    case TokenKind::Tilde: return "Tilde";
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
    if (c == '.' && isDigit(peek(1))) return lexNumber();  // .5, .25e3
    if (c == '"') return lexString();
    if (c == '\'') return lexChar();

    // One- or two-character operators and punctuation.
    advance();
    switch (c) {
    case '(': return finish(TokenKind::LParen, start, loc);
    case ')': return finish(TokenKind::RParen, start, loc);
    case '{': return finish(TokenKind::LBrace, start, loc);
    case '}': return finish(TokenKind::RBrace, start, loc);
    case '[': return finish(TokenKind::LBracket, start, loc);
    case ']': return finish(TokenKind::RBracket, start, loc);
    case '.': return finish(TokenKind::Dot, start, loc);
    case ',': return finish(TokenKind::Comma, start, loc);
    case ':': return finish(TokenKind::Colon, start, loc);
    case ';': return finish(TokenKind::Semicolon, start, loc);
    case '+': return finish(TokenKind::Plus, start, loc);
    case '-':
        if (peek() == '>') {
            advance();
            return finish(TokenKind::Arrow, start, loc);
        }
        return finish(TokenKind::Minus, start, loc);
    case '*': return finish(TokenKind::Star, start, loc);
    case '/': return finish(TokenKind::Slash, start, loc);
    case '%': return finish(TokenKind::Percent, start, loc);
    case '&': return finish(TokenKind::Amp, start, loc);
    case '|': return finish(TokenKind::Pipe, start, loc);
    case '^': return finish(TokenKind::Caret, start, loc);
    case '~': return finish(TokenKind::Tilde, start, loc);
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

// Numbers: decimal and hex integers (`42`, `0x2A`), floats (`1.0`, `.5`,
// `2.5e-3`, `3.14f`), and either with a type suffix (`42u32`, `-1i8` lexes the
// `1i8`). A leading '.' is only reached here when the next char is a digit.
Token Lexer::lexNumber() {
    const std::size_t start = offset_;
    const SourceLocation loc{line_, column_};

    // Hex integer: `0x` / `0X` then hex digits. No hex floats.
    if (peek() == '0' && (peek(1) == 'x' || peek(1) == 'X')) {
        advance();  // 0
        advance();  // x
        const std::size_t digitsStart = offset_;
        while (isHexDigit(peek())) advance();
        if (offset_ == digitsStart) {
            diags_.error(loc, "hexadecimal literal has no digits after '0x'");
            Token t = finish(TokenKind::Error, start, loc);
            t.stringValue = "empty hexadecimal literal";
            return t;
        }
        const llvm::StringRef digits =
            source_.substr(digitsStart, offset_ - digitsStart);
        Token t = finishNumberToken(TokenKind::IntLiteral, start, loc);
        std::uint64_t value = 0;
        if (digits.getAsInteger(16, value)) {
            diags_.error(loc, llvm::Twine("hexadecimal literal '") + t.spelling +
                                  "' does not fit in 64 bits");
            t.kind = TokenKind::Error;
            t.stringValue = "hexadecimal literal out of range";
            return t;
        }
        t.intValue = static_cast<std::int64_t>(value);
        return validateSuffixedInt(t, loc);
    }

    // Decimal integer or float.
    bool isFloat = false;
    while (isDigit(peek())) advance();
    if (peek() == '.' && isDigit(peek(1))) {
        isFloat = true;
        advance();  // .
        while (isDigit(peek())) advance();
    } else if (peek() == '.' && offset_ == start) {
        // Reached via the `.digit` entry: the '.' is the first char.
        isFloat = true;
        advance();  // .
        while (isDigit(peek())) advance();
    }
    if (peek() == 'e' || peek() == 'E') {
        const char sign = peek(1);
        const bool signed_ = sign == '+' || sign == '-';
        if (isDigit(peek(1)) || (signed_ && isDigit(peek(2)))) {
            isFloat = true;
            advance();                 // e
            if (signed_) advance();    // + / -
            while (isDigit(peek())) advance();
        }
    }

    if (isFloat) {
        bool isF32 = false;
        if (peek() == 'f') {
            isF32 = true;
            advance();
        }
        Token t = finishNumberToken(TokenKind::FloatLiteral, start, loc);
        const llvm::StringRef digits =
            isF32 ? t.spelling.drop_back(1) : llvm::StringRef(t.spelling);
        double value = 0.0;
        if (digits.getAsDouble(value)) {
            diags_.error(loc, llvm::Twine("malformed floating-point literal '") +
                                  t.spelling + "'");
            t.kind = TokenKind::Error;
            t.stringValue = "malformed floating-point literal";
            return t;
        }
        t.floatValue = value;
        t.floatIsF32 = isF32;
        return t;
    }

    Token t = finishNumberToken(TokenKind::IntLiteral, start, loc);
    const llvm::StringRef digits = digitsBeforeSuffix(t.spelling);
    std::uint64_t value = 0;
    const auto maxSigned =
        static_cast<std::uint64_t>(std::numeric_limits<std::int64_t>::max());
    if (digits.getAsInteger(10, value) || value > maxSigned) {
        diags_.error(loc, llvm::Twine("integer literal '") + t.spelling +
                              "' does not fit in a 64-bit signed integer");
        t.kind = TokenKind::Error;
        t.stringValue = "integer literal out of range";
        return t;
    }
    t.intValue = static_cast<std::int64_t>(value);
    return validateSuffixedInt(t, loc);
}

// Consumes a trailing integer type suffix (`i8`..`i64`, `u8`..`u64`) if one is
// present, then builds the token spanning the whole thing.
Token Lexer::finishNumberToken(TokenKind kind, std::size_t start,
                               SourceLocation loc) {
    if ((peek() == 'i' || peek() == 'u') && isDigit(peek(1))) {
        advance();                       // i / u
        while (isDigit(peek())) advance();
    }
    return finish(kind, start, loc);
}

// Given a full literal spelling, returns just the digits (drops an `i*`/`u*`
// suffix). Used for the decimal-integer parse.
llvm::StringRef Lexer::digitsBeforeSuffix(llvm::StringRef spelling) {
    const std::size_t i = spelling.find_first_of("iu");
    return i == llvm::StringRef::npos ? spelling : spelling.take_front(i);
}

// Fills in the intSuffix* fields from the token's spelling and range-checks the
// value against the suffix type. `t` already has intValue set.
Token Lexer::validateSuffixedInt(Token &t, SourceLocation loc) {
    const std::size_t i = t.spelling.find_first_of("iu");
    if (i == llvm::StringRef::npos) return t;  // bare literal, defaults to `int`

    const bool sign = t.spelling[i] == 'i';
    unsigned bits = 0;
    if (t.spelling.substr(i + 1).getAsInteger(10, bits) ||
        (bits != 8 && bits != 16 && bits != 32 && bits != 64)) {
        diags_.error(loc, llvm::Twine("unknown integer suffix '") +
                              t.spelling.substr(i) +
                              "' (expected i8/i16/i32/i64 or u8/u16/u32/u64)");
        t.kind = TokenKind::Error;
        t.stringValue = "unknown integer suffix";
        return t;
    }

    const auto uvalue = static_cast<std::uint64_t>(t.intValue);
    std::uint64_t limit;
    if (sign)
        limit = bits == 64 ? static_cast<std::uint64_t>(
                                 std::numeric_limits<std::int64_t>::max())
                           : (1ULL << (bits - 1)) - 1;
    else
        limit = bits == 64 ? ~0ULL : (1ULL << bits) - 1;
    if (uvalue > limit) {
        diags_.error(loc, llvm::Twine("integer literal '") + t.spelling +
                              "' does not fit in " + (sign ? "i" : "u") +
                              llvm::Twine(bits));
        t.kind = TokenKind::Error;
        t.stringValue = "integer literal out of range for its suffix";
        return t;
    }

    t.intSuffixBits = bits;
    t.intSuffixSigned = sign;
    return t;
}

// Character literal: `'A'`, `'\n'`, `'\0'`. One byte, the same escapes strings
// allow. The value goes in Token::intValue.
Token Lexer::lexChar() {
    const std::size_t start = offset_;
    const SourceLocation loc{line_, column_};

    advance();  // opening quote
    const std::size_t bodyStart = offset_;
    while (!atEnd() && peek() != '\'' && peek() != '\n') {
        if (peek() == '\\') {
            advance();
            if (!atEnd() && peek() != '\n') advance();
        } else {
            advance();
        }
    }
    if (atEnd() || peek() == '\n') {
        diags_.error(loc, "unterminated character literal");
        Token t = finish(TokenKind::Error, start, loc);
        t.stringValue = "unterminated character literal";
        return t;
    }
    const llvm::StringRef body = source_.substr(bodyStart, offset_ - bodyStart);
    advance();  // closing quote

    Token t = finish(TokenKind::CharLiteral, start, loc);
    std::string decoded;
    std::size_t errorOffset = 0;
    if (!decodeStringEscapes(body, decoded, &errorOffset)) {
        diags_.error(loc, "invalid escape sequence in character literal "
                          "(allowed: \\n \\t \\r \\\\ \\' \\0)");
        t.kind = TokenKind::Error;
        t.stringValue = "invalid escape sequence";
        return t;
    }
    if (decoded.size() != 1) {
        diags_.error(loc, llvm::Twine("character literal must be exactly one "
                                      "byte (got ") +
                              llvm::Twine(decoded.size()) + ")");
        t.kind = TokenKind::Error;
        t.stringValue = "character literal is not one byte";
        return t;
    }
    t.intValue = static_cast<unsigned char>(decoded[0]);
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
                          "(allowed: \\n \\t \\r \\\\ \\\" \\' \\0)");
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
                 .Case("let", TokenKind::KwLet)
                 .Case("check", TokenKind::KwCheck)
                 .Case("else", TokenKind::KwElse)
                 .Case("otherwise", TokenKind::KwOtherwise)
                 .Case("while", TokenKind::KwWhile)
                 .Case("return", TokenKind::KwReturn)
                 .Case("stop", TokenKind::KwStop)
                 .Case("skip", TokenKind::KwSkip)
                 .Case("struct", TokenKind::KwStruct)
                 .Case("extern", TokenKind::KwExtern)
                 .Case("to", TokenKind::KwTo)
                 .Case("yes", TokenKind::KwYes)
                 .Case("no", TokenKind::KwNo)
                 .Case("none", TokenKind::KwNone)
                 .Case("sizeof", TokenKind::KwSizeof)
                 .Case("offsetof", TokenKind::KwOffsetof)
                 .Default(TokenKind::Identifier);
    return t;
}

}  // namespace jocky
