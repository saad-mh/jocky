#include "jocky/parser/Parser.h"

#include "jocky/Support/Diagnostic.h"

#include <llvm/ADT/Twine.h>

#include <string>

namespace jocky {

namespace {

constexpr std::size_t kMaxErrors = 20;

// A short description of a token for error messages: its text in quotes, or a
// friendly name when it has none.
std::string describeToken(const Token &t) {
    if (t.kind == TokenKind::Eof) return "end of file";
    if (!t.spelling.empty()) return (llvm::Twine("'") + t.spelling + "'").str();
    return tokenKindName(t.kind).str();
}

}  // namespace

Parser::Parser(llvm::ArrayRef<Token> tokens, DiagnosticEngine &diags)
    : tokens_(tokens), diags_(diags) {}

// token cursor

const Token &Parser::peek(std::size_t ahead) const {
    std::size_t i = pos_ + ahead;
    if (i >= tokens_.size()) i = tokens_.size() - 1;  // clamp to the eof token
    return tokens_[i];
}

const Token &Parser::advance() {
    const Token &t = current();
    if (pos_ + 1 < tokens_.size()) ++pos_;
    return t;
}

bool Parser::match(TokenKind kind) {
    if (!check(kind)) return false;
    advance();
    return true;
}

bool Parser::expect(TokenKind kind, const char *what) {
    if (match(kind)) return true;
    diags_.error(current().location, llvm::Twine("expected ") + what +
                                         " but found " +
                                         describeToken(current()));
    return false;
}

bool Parser::tooManyErrors() const { return diags_.errorCount() >= kMaxErrors; }

void Parser::synchronize() {
    if (atEnd()) return;
    advance();  // always move past the token that triggered the error

    while (!atEnd()) {
        // We just consumed a ';' - a statement boundary, so resume here.
        if (pos_ > 0 && tokens_[pos_ - 1].kind == TokenKind::Semicolon) return;

        // We are sitting on something that can start a fresh construct.
        switch (current().kind) {
        case TokenKind::KwFunc:
        case TokenKind::KwVar:
        case TokenKind::KwIf:
        case TokenKind::KwWhile:
        case TokenKind::KwReturn:
        case TokenKind::RBrace:
            return;
        default:
            advance();
        }
    }
}

// grammar rules

std::unique_ptr<ast::Module> Parser::parseModule() {
    module_ = std::make_unique<ast::Module>();

    while (!atEnd() && !tooManyErrors()) {
        // `link "name";` pragma - a contextual keyword at top level only.
        if (check(TokenKind::Identifier) && current().spelling == "link" &&
            peek(1).kind == TokenKind::StringLiteral) {
            advance();  // 'link'
            module_->linkLibs.push_back(current().stringValue);
            advance();  // the string
            if (!expect(TokenKind::Semicolon, "';' after the link pragma"))
                synchronize();
            continue;
        }
        if (check(TokenKind::KwStruct)) {
            if (ast::StructDecl *s = parseStructDecl())
                module_->structs.push_back(s);
            else
                synchronize();
        } else if (check(TokenKind::KwExtern)) {
            if (ast::ExternDecl *e = parseExternDecl())
                module_->externs.push_back(e);
            else
                synchronize();
        } else if (check(TokenKind::KwFunc)) {
            if (ast::FunctionDecl *fn = parseFunctionDecl())
                module_->functions.push_back(fn);
            else
                synchronize();
        } else {
            if (ast::Stmt *s = parseStatement())
                module_->topLevelStatements.push_back(s);
            else
                synchronize();
        }
    }

    return std::move(module_);
}

// `struct Name { field: type, field: type, }` - `,` separates fields and may
// trail; a newline does not (JOCKY is not newline-sensitive).
ast::StructDecl *Parser::parseStructDecl() {
    const SourceLocation loc = current().location;
    advance();  // 'struct'

    if (!check(TokenKind::Identifier)) {
        diags_.error(current().location, "expected a struct name after 'struct'");
        return nullptr;
    }
    auto *decl = make<ast::StructDecl>(loc, current().spelling.str());
    advance();

    if (!expect(TokenKind::LBrace, "'{' to open the struct body")) return nullptr;
    while (!check(TokenKind::RBrace) && !atEnd() && !tooManyErrors()) {
        if (!check(TokenKind::Identifier)) {
            diags_.error(current().location, "expected a field name");
            return nullptr;
        }
        ast::FieldDecl f;
        f.name = current().spelling.str();
        f.loc = current().location;
        advance();
        if (!expect(TokenKind::Colon, "':' and a type after the field name"))
            return nullptr;
        f.typeAnnotation = parseType();
        if (!f.typeAnnotation) return nullptr;
        decl->fields.push_back(std::move(f));
        if (!match(TokenKind::Comma)) break;
    }
    if (!expect(TokenKind::RBrace, "'}' to close the struct body")) return nullptr;
    return decl;
}

// `extern "C" name(out? p: type, ..., ...) -> type;` - no body.
ast::ExternDecl *Parser::parseExternDecl() {
    const SourceLocation loc = current().location;
    advance();  // 'extern'

    if (!check(TokenKind::StringLiteral) || current().stringValue != "C") {
        diags_.error(current().location,
                     "expected \"C\" after 'extern' (the only calling "
                     "convention supported)");
        return nullptr;
    }
    advance();  // "C"

    if (!check(TokenKind::Identifier)) {
        diags_.error(current().location, "expected a function name");
        return nullptr;
    }
    auto *decl = make<ast::ExternDecl>(loc, current().spelling.str());
    advance();

    if (!expect(TokenKind::LParen, "'(' after the function name")) return nullptr;
    if (!check(TokenKind::RParen)) {
        for (;;) {
            if (check(TokenKind::Dot) && peek(1).kind == TokenKind::Dot &&
                peek(2).kind == TokenKind::Dot) {
                advance();
                advance();
                advance();
                decl->isVarArg = true;
                break;
            }
            ast::Param p;
            // `out` is the marker only when a real `name : type` follows it;
            // otherwise `out` is itself the parameter name.
            if (check(TokenKind::Identifier) && current().spelling == "out" &&
                peek(1).kind == TokenKind::Identifier &&
                peek(2).kind == TokenKind::Colon) {
                p.isOut = true;
                advance();
            }
            if (!check(TokenKind::Identifier)) {
                diags_.error(current().location, "expected a parameter name");
                return nullptr;
            }
            p.name = current().spelling.str();
            p.loc = current().location;
            advance();
            if (!expect(TokenKind::Colon, "':' and a type after the parameter "
                                          "name"))
                return nullptr;
            p.typeAnnotation = parseType();
            if (!p.typeAnnotation) return nullptr;
            decl->params.push_back(std::move(p));
            if (!match(TokenKind::Comma)) break;
        }
    }
    if (!expect(TokenKind::RParen, "')' after the parameter list")) return nullptr;

    if (match(TokenKind::Arrow)) {
        decl->returnType = parseType();
        if (!decl->returnType) return nullptr;
    }
    if (!expect(TokenKind::Semicolon, "';' after the extern declaration"))
        return nullptr;
    return decl;
}

ast::FunctionDecl *Parser::parseFunctionDecl() {
    const SourceLocation loc = current().location;
    advance();  // 'func'

    if (!check(TokenKind::Identifier)) {
        diags_.error(current().location, "expected a function name after 'func'");
        return nullptr;
    }
    std::string name = current().spelling.str();
    advance();

    auto *fn = make<ast::FunctionDecl>(loc, std::move(name));

    if (!expect(TokenKind::LParen, "'(' after the function name")) return nullptr;
    if (!check(TokenKind::RParen)) {
        for (;;) {
            if (!check(TokenKind::Identifier)) {
                diags_.error(current().location, "expected a parameter name");
                return nullptr;
            }
            ast::Param p;
            p.name = current().spelling.str();
            p.loc = current().location;
            advance();
            // The type annotation is optional in the grammar so that a missing
            // one is a semantic diagnostic ("parameter 'p' needs a type"), not a
            // parse error.
            if (match(TokenKind::Colon)) {
                p.typeAnnotation = parseType();
                if (!p.typeAnnotation) return nullptr;
            }
            fn->params.push_back(std::move(p));
            if (!match(TokenKind::Comma)) break;
        }
    }
    if (!expect(TokenKind::RParen, "')' after the parameter list")) return nullptr;

    // Optional `-> Type`; its absence means `-> int`.
    if (match(TokenKind::Arrow)) {
        fn->returnType = parseType();
        if (!fn->returnType) return nullptr;
    }

    ast::Block *body = parseBlock();
    if (!body) return nullptr;
    fn->body = body;
    return fn;
}

// A type in annotation position: a name (`int`, `u32`, `rawptr`), the generic
// `ptr<T>`, and any run of `[N]` (fixed array) / `[]` (slice) suffixes, applied
// left to right. Sema resolves the name and folds the size expression.
ast::TypeExpr *Parser::parseType() {
    if (!check(TokenKind::Identifier)) {
        diags_.error(current().location,
                     llvm::Twine("expected a type name but found ") +
                         describeToken(current()));
        return nullptr;
    }
    const SourceLocation loc = current().location;
    ast::TypeExpr *ty = make<ast::TypeExpr>(loc, current().spelling.str());
    advance();

    // `ptr<T>`. `>` is a single token here (JOCKY never lexes `>>`), so
    // `ptr<ptr<int>>` closes naturally.
    if (ty->name == "ptr" && check(TokenKind::Lt)) {
        advance();  // '<'
        ast::TypeExpr *pointee = parseType();
        if (!pointee) return nullptr;
        if (!expect(TokenKind::Gt, "'>' to close 'ptr<...>'")) return nullptr;
        ty = make<ast::TypeExpr>(loc, ast::TypeExpr::Form::Pointer, pointee,
                                 nullptr);
    }

    while (check(TokenKind::LBracket)) {
        const SourceLocation bloc = current().location;
        advance();  // '['
        if (match(TokenKind::RBracket)) {
            ty = make<ast::TypeExpr>(bloc, ast::TypeExpr::Form::Slice, ty,
                                     nullptr);
            continue;
        }
        ast::Expr *size = parseExpr();
        if (!size) return nullptr;
        if (!expect(TokenKind::RBracket, "']' after the array length"))
            return nullptr;
        ty = make<ast::TypeExpr>(bloc, ast::TypeExpr::Form::Array, ty, size);
    }
    return ty;
}

ast::Block *Parser::parseBlock() {
    const SourceLocation loc = current().location;
    if (!expect(TokenKind::LBrace, "'{'")) return nullptr;

    auto *block = make<ast::Block>(loc);
    while (!check(TokenKind::RBrace) && !atEnd() && !tooManyErrors()) {
        if (ast::Stmt *s = parseStatement())
            block->statements.push_back(s);
        else
            synchronize();
    }

    if (!expect(TokenKind::RBrace, "'}' to close the block")) return nullptr;
    return block;
}

ast::Stmt *Parser::parseStatement() {
    switch (current().kind) {
    case TokenKind::KwVar: return parseVarDecl();
    case TokenKind::KwIf: return parseIf();
    case TokenKind::KwWhile: return parseWhile();
    case TokenKind::KwReturn: return parseReturn();
    case TokenKind::LBrace: return parseBlock();
    default: return parseAssignOrExprStatement();
    }
}

ast::Stmt *Parser::parseVarDecl() {
    const SourceLocation loc = current().location;
    advance();  // 'var'

    if (!check(TokenKind::Identifier)) {
        diags_.error(current().location, "expected a variable name after 'var'");
        return nullptr;
    }
    std::string name = current().spelling.str();
    advance();

    ast::TypeExpr *annotation = nullptr;
    if (match(TokenKind::Colon)) {
        annotation = parseType();
        if (!annotation) return nullptr;
    }

    // The initializer is optional only when a type was given
    // (`var buf: char[4096];`); otherwise there is nothing to infer from.
    ast::Expr *init = nullptr;
    if (match(TokenKind::Assign)) {
        init = parseExpr();
        if (!init) return nullptr;
    } else if (!annotation) {
        diags_.error(current().location,
                     "a variable needs a type or an initializer");
        return nullptr;
    } else if (!check(TokenKind::Semicolon)) {
        diags_.error(current().location,
                     llvm::Twine("expected '=' or ';' after the variable "
                                 "declaration but found ") +
                         describeToken(current()));
        return nullptr;
    }

    if (!expect(TokenKind::Semicolon, "';' after the variable declaration"))
        return nullptr;

    auto *decl = make<ast::VarDeclStmt>(loc, std::move(name), init);
    decl->typeAnnotation = annotation;
    return decl;
}

ast::Stmt *Parser::parseAssignOrExprStatement() {
    const SourceLocation loc = current().location;
    ast::Expr *e = parseExpr();
    if (!e) return nullptr;

    // `lvalue = expr ;` - a bare '=' after a full expression is an assignment.
    // Whether the left side is actually assignable is a semantic question.
    if (match(TokenKind::Assign)) {
        ast::Expr *value = parseExpr();
        if (!value) return nullptr;
        if (!expect(TokenKind::Semicolon, "';' after the assignment"))
            return nullptr;
        return make<ast::AssignStmt>(loc, e, value);
    }

    // Otherwise: expr ';'  (covers `print(x);` and other bare calls).
    if (!expect(TokenKind::Semicolon, "';' after the expression")) return nullptr;
    return make<ast::ExprStmt>(loc, e);
}

ast::Stmt *Parser::parseIf() {
    const SourceLocation loc = current().location;
    advance();  // 'if'

    if (!expect(TokenKind::LParen, "'(' after 'if'")) return nullptr;
    ast::Expr *cond = parseExpr();
    if (!cond) return nullptr;
    if (!expect(TokenKind::RParen, "')' after the condition")) return nullptr;

    ast::Block *thenBlk = parseBlock();
    if (!thenBlk) return nullptr;

    ast::Block *elseBlk = nullptr;
    if (match(TokenKind::KwElse)) {
        if (check(TokenKind::KwIf)) {
            // Store `else if ...` as a block containing the nested if.
            const SourceLocation elseLoc = current().location;
            ast::Stmt *nested = parseIf();
            if (!nested) return nullptr;
            auto *wrap = make<ast::Block>(elseLoc);
            wrap->statements.push_back(nested);
            elseBlk = wrap;
        } else {
            elseBlk = parseBlock();
            if (!elseBlk) return nullptr;
        }
    }

    return make<ast::IfStmt>(loc, cond, thenBlk, elseBlk);
}

ast::Stmt *Parser::parseWhile() {
    const SourceLocation loc = current().location;
    advance();  // 'while'

    if (!expect(TokenKind::LParen, "'(' after 'while'")) return nullptr;
    ast::Expr *cond = parseExpr();
    if (!cond) return nullptr;
    if (!expect(TokenKind::RParen, "')' after the condition")) return nullptr;

    ast::Block *body = parseBlock();
    if (!body) return nullptr;

    return make<ast::WhileStmt>(loc, cond, body);
}

ast::Stmt *Parser::parseReturn() {
    const SourceLocation loc = current().location;
    advance();  // 'return'

    ast::Expr *value = nullptr;
    if (!check(TokenKind::Semicolon)) {
        value = parseExpr();
        if (!value) return nullptr;
    }
    if (!expect(TokenKind::Semicolon, "';' after 'return'")) return nullptr;

    return make<ast::ReturnStmt>(loc, value);
}

// expressions (precedence climbing, l to h). Lowest to highest:
//   |  ^  &  ==/!=  </<=/>/>=  <</>>  +/-  *//%  as  unary -/~  postfix []/.

ast::Expr *Parser::parseExpr() { return parseBitOr(); }

ast::Expr *Parser::parseBitOr() {
    ast::Expr *left = parseBitXor();
    if (!left) return nullptr;
    while (check(TokenKind::Pipe)) {
        const SourceLocation loc = current().location;
        advance();
        ast::Expr *right = parseBitXor();
        if (!right) return nullptr;
        left = make<ast::BinaryExpr>(loc, ast::BinaryOp::BitOr, left, right);
    }
    return left;
}

ast::Expr *Parser::parseBitXor() {
    ast::Expr *left = parseBitAnd();
    if (!left) return nullptr;
    while (check(TokenKind::Caret)) {
        const SourceLocation loc = current().location;
        advance();
        ast::Expr *right = parseBitAnd();
        if (!right) return nullptr;
        left = make<ast::BinaryExpr>(loc, ast::BinaryOp::BitXor, left, right);
    }
    return left;
}

ast::Expr *Parser::parseBitAnd() {
    ast::Expr *left = parseEquality();
    if (!left) return nullptr;
    while (check(TokenKind::Amp)) {
        const SourceLocation loc = current().location;
        advance();
        ast::Expr *right = parseEquality();
        if (!right) return nullptr;
        left = make<ast::BinaryExpr>(loc, ast::BinaryOp::BitAnd, left, right);
    }
    return left;
}

ast::Expr *Parser::parseEquality() {
    ast::Expr *left = parseRelational();
    if (!left) return nullptr;
    for (;;) {
        ast::BinaryOp op;
        if (check(TokenKind::EqEq)) {
            op = ast::BinaryOp::Eq;
        } else if (check(TokenKind::NotEq)) {
            op = ast::BinaryOp::Ne;
        } else {
            return left;
        }
        const SourceLocation loc = current().location;
        advance();
        ast::Expr *right = parseRelational();
        if (!right) return nullptr;
        left = make<ast::BinaryExpr>(loc, op, left, right);
    }
}

ast::Expr *Parser::parseRelational() {
    ast::Expr *left = parseShift();
    if (!left) return nullptr;
    for (;;) {
        // `<` / `>` here is relational only when it is *not* the first half of a
        // `<<` / `>>` shift (two adjacent tokens).
        ast::BinaryOp op;
        if (check(TokenKind::Lt) && !twoAdjacent(TokenKind::Lt)) {
            op = ast::BinaryOp::Lt;
        } else if (check(TokenKind::LtEq)) {
            op = ast::BinaryOp::Le;
        } else if (check(TokenKind::Gt) && !twoAdjacent(TokenKind::Gt)) {
            op = ast::BinaryOp::Gt;
        } else if (check(TokenKind::GtEq)) {
            op = ast::BinaryOp::Ge;
        } else {
            return left;
        }
        const SourceLocation loc = current().location;
        advance();
        ast::Expr *right = parseShift();
        if (!right) return nullptr;
        left = make<ast::BinaryExpr>(loc, op, left, right);
    }
}

// `<<` and `>>` are two adjacent `<` / `>` tokens (JOCKY never lexes them as
// one, so `ptr<ptr<int>>` closes cleanly). "Adjacent" means no space between.
bool Parser::twoAdjacent(TokenKind kind) const {
    if (current().kind != kind || peek(1).kind != kind) return false;
    const SourceLocation a = current().location;
    const SourceLocation b = peek(1).location;
    return a.line == b.line && a.column + 1 == b.column;
}

ast::Expr *Parser::parseShift() {
    ast::Expr *left = parseAdditive();
    if (!left) return nullptr;
    for (;;) {
        ast::BinaryOp op;
        if (twoAdjacent(TokenKind::Lt)) {
            op = ast::BinaryOp::Shl;
        } else if (twoAdjacent(TokenKind::Gt)) {
            op = ast::BinaryOp::Shr;
        } else {
            return left;
        }
        const SourceLocation loc = current().location;
        advance();  // first < / >
        advance();  // second < / >
        ast::Expr *right = parseAdditive();
        if (!right) return nullptr;
        left = make<ast::BinaryExpr>(loc, op, left, right);
    }
}

ast::Expr *Parser::parseAdditive() {
    ast::Expr *left = parseMultiplicative();
    if (!left) return nullptr;
    for (;;) {
        ast::BinaryOp op;
        if (check(TokenKind::Plus)) {
            op = ast::BinaryOp::Add;
        } else if (check(TokenKind::Minus)) {
            op = ast::BinaryOp::Sub;
        } else {
            return left;
        }
        const SourceLocation loc = current().location;
        advance();
        ast::Expr *right = parseMultiplicative();
        if (!right) return nullptr;
        left = make<ast::BinaryExpr>(loc, op, left, right);
    }
}

ast::Expr *Parser::parseMultiplicative() {
    ast::Expr *left = parseCast();
    if (!left) return nullptr;
    for (;;) {
        ast::BinaryOp op;
        if (check(TokenKind::Star)) {
            op = ast::BinaryOp::Mul;
        } else if (check(TokenKind::Slash)) {
            op = ast::BinaryOp::Div;
        } else if (check(TokenKind::Percent)) {
            op = ast::BinaryOp::Mod;
        } else {
            return left;
        }
        const SourceLocation loc = current().location;
        advance();
        ast::Expr *right = parseCast();
        if (!right) return nullptr;
        left = make<ast::BinaryExpr>(loc, op, left, right);
    }
}

// `unary ('as' type)*` - a cast binds tighter than the arithmetic operators and
// looser than a prefix `-`, so `-x as int` is `(-x) as int` and `a * b as int`
// is `a * (b as int)`.
ast::Expr *Parser::parseCast() {
    ast::Expr *e = parseUnary();
    if (!e) return nullptr;
    while (check(TokenKind::KwAs)) {
        const SourceLocation loc = current().location;
        advance();  // 'as'
        ast::TypeExpr *target = parseType();
        if (!target) return nullptr;
        e = make<ast::CastExpr>(loc, e, target);
    }
    return e;
}

ast::Expr *Parser::parseUnary() {
    if (check(TokenKind::Minus) || check(TokenKind::Tilde)) {
        const ast::UnaryOp op = check(TokenKind::Tilde) ? ast::UnaryOp::BitNot
                                                        : ast::UnaryOp::Neg;
        const SourceLocation loc = current().location;
        advance();
        ast::Expr *operand = parseUnary();
        if (!operand) return nullptr;
        return make<ast::UnaryExpr>(loc, op, operand);
    }
    // Prefix `&` (address-of) and `*` (dereference). In expression position
    // these are unambiguous against the infix `&` / `*` operators.
    if (check(TokenKind::Amp)) {
        const SourceLocation loc = current().location;
        advance();
        ast::Expr *operand = parseUnary();
        if (!operand) return nullptr;
        return make<ast::AddrOfExpr>(loc, operand);
    }
    if (check(TokenKind::Star)) {
        const SourceLocation loc = current().location;
        advance();
        ast::Expr *operand = parseUnary();
        if (!operand) return nullptr;
        return make<ast::DerefExpr>(loc, operand);
    }
    return parsePostfix();
}

// `primary` followed by any run of `[index]`, `[lo:hi]`, and `.member`.
ast::Expr *Parser::parsePostfix() {
    ast::Expr *e = parsePrimary();
    if (!e) return nullptr;

    for (;;) {
        if (check(TokenKind::LBracket)) {
            const SourceLocation loc = current().location;
            advance();  // '['

            ast::Expr *lo = nullptr;
            ast::Expr *hi = nullptr;

            if (check(TokenKind::Colon)) {
                advance();  // ':'
                if (!check(TokenKind::RBracket)) {
                    hi = parseExpr();
                    if (!hi) return nullptr;
                }
            } else {
                ast::Expr *first = parseExpr();
                if (!first) return nullptr;
                if (match(TokenKind::Colon)) {
                    lo = first;
                    if (!check(TokenKind::RBracket)) {
                        hi = parseExpr();
                        if (!hi) return nullptr;
                    }
                } else {
                    if (!expect(TokenKind::RBracket, "']' after the index"))
                        return nullptr;
                    e = make<ast::IndexExpr>(loc, e, first);
                    continue;
                }
            }

            if (!expect(TokenKind::RBracket, "']' after the slice bounds"))
                return nullptr;
            e = make<ast::SliceExpr>(loc, e, lo, hi);
            continue;
        }

        if (check(TokenKind::Dot)) {
            const SourceLocation loc = current().location;
            advance();  // '.'
            if (!check(TokenKind::Identifier)) {
                diags_.error(current().location,
                             "expected a member name after '.'");
                return nullptr;
            }
            std::string member = current().spelling.str();
            advance();
            e = make<ast::MemberExpr>(loc, e, std::move(member));
            continue;
        }

        return e;
    }
}

ast::Expr *Parser::parsePrimary() {
    const Token &tok = current();

    switch (tok.kind) {
    case TokenKind::IntLiteral: {
        advance();
        auto *lit = make<ast::IntLiteralExpr>(tok.location, tok.intValue);
        lit->suffixBits = tok.intSuffixBits;
        lit->suffixSigned = tok.intSuffixSigned;
        return lit;
    }

    case TokenKind::FloatLiteral:
        advance();
        return make<ast::FloatLiteralExpr>(tok.location, tok.floatValue,
                                           tok.floatIsF32);

    case TokenKind::CharLiteral:
        advance();
        return make<ast::CharLiteralExpr>(
            tok.location, static_cast<std::uint8_t>(tok.intValue));

    case TokenKind::KwTrue:
        advance();
        return make<ast::BoolLiteralExpr>(tok.location, true);

    case TokenKind::KwFalse:
        advance();
        return make<ast::BoolLiteralExpr>(tok.location, false);

    case TokenKind::KwNull:
        advance();
        return make<ast::NullLiteralExpr>(tok.location);

    case TokenKind::KwOffsetof: {
        const SourceLocation loc = tok.location;
        advance();  // 'offsetof'
        if (!expect(TokenKind::LParen, "'(' after 'offsetof'")) return nullptr;
        if (!check(TokenKind::Identifier)) {
            diags_.error(current().location, "expected a struct name");
            return nullptr;
        }
        std::string sname = current().spelling.str();
        advance();
        if (!expect(TokenKind::Comma, "',' between the struct and field names"))
            return nullptr;
        if (!check(TokenKind::Identifier)) {
            diags_.error(current().location, "expected a field name");
            return nullptr;
        }
        std::string fname = current().spelling.str();
        advance();
        if (!expect(TokenKind::RParen, "')' to close 'offsetof(...)'"))
            return nullptr;
        return make<ast::OffsetofExpr>(loc, std::move(sname), std::move(fname));
    }

    case TokenKind::KwSizeof: {
        const SourceLocation loc = tok.location;
        advance();  // 'sizeof'
        if (!expect(TokenKind::LParen, "'(' after 'sizeof'")) return nullptr;

        auto *node = make<ast::SizeofExpr>(loc);
        // Try to read a type; if that consumes exactly up to `)`, it was
        // `sizeof(T)`. Otherwise rewind and read an expression.
        const std::size_t savedPos = pos_;
        const std::size_t savedDiag = diags_.mark();
        ast::TypeExpr *asType = parseType();
        if (asType && check(TokenKind::RParen)) {
            node->typeArg = asType;
        } else {
            pos_ = savedPos;
            diags_.rewind(savedDiag);
            node->exprArg = parseExpr();
            if (!node->exprArg) return nullptr;
        }
        if (!expect(TokenKind::RParen, "')' to close 'sizeof(...)'"))
            return nullptr;
        return node;
    }

    case TokenKind::StringLiteral:
        advance();
        return make<ast::StringLiteralExpr>(tok.location, tok.stringValue);

    case TokenKind::LBracket: {
        const SourceLocation loc = tok.location;
        advance();  // '['
        auto *lit = make<ast::ArrayLiteralExpr>(loc);
        if (!check(TokenKind::RBracket)) {
            for (;;) {
                ast::Expr *el = parseExpr();
                if (!el) return nullptr;
                lit->elements.push_back(el);
                if (!match(TokenKind::Comma)) break;
            }
        }
        if (!expect(TokenKind::RBracket, "']' to close the array literal"))
            return nullptr;
        return lit;
    }

    case TokenKind::Identifier: {
        std::string name = tok.spelling.str();
        const SourceLocation loc = tok.location;
        advance();

        if (match(TokenKind::LParen)) {
            auto *call = make<ast::CallExpr>(loc, std::move(name));
            if (!check(TokenKind::RParen)) {
                for (;;) {
                    ast::Expr *arg = parseExpr();
                    if (!arg) return nullptr;
                    call->args.push_back(arg);
                    if (!match(TokenKind::Comma)) break;
                }
            }
            if (!expect(TokenKind::RParen, "')' after the call arguments"))
                return nullptr;
            return call;
        }

        return make<ast::VarRefExpr>(loc, std::move(name));
    }

    case TokenKind::LParen: {
        advance();
        ast::Expr *inner = parseExpr();
        if (!inner) return nullptr;
        if (!expect(TokenKind::RParen,
                    "')' to close the parenthesized expression"))
            return nullptr;
        return inner;
    }

    case TokenKind::Error:
        // The lexer already reported this; consume and fail quietly.
        advance();
        return nullptr;

    default:
        diags_.error(tok.location, llvm::Twine("expected an expression but found ") +
                                       describeToken(tok));
        return nullptr;
    }
}

}  // namespace jocky
