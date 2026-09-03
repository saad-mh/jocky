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

// --- token cursor ---------------------------------------------------

const Token &Parser::peek(std::size_t ahead) const {
    std::size_t i = pos_ + ahead;
    if (i >= tokens_.size()) i = tokens_.size() - 1;  // clamp to the Eof token
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

// --- grammar rules -----------------------------------------------

std::unique_ptr<ast::Module> Parser::parseModule() {
    module_ = std::make_unique<ast::Module>();

    while (!atEnd() && !tooManyErrors()) {
        if (check(TokenKind::KwFunc)) {
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
            fn->params.push_back(
                ast::Param{current().spelling.str(), current().location});
            advance();
            if (!match(TokenKind::Comma)) break;
        }
    }
    if (!expect(TokenKind::RParen, "')' after the parameter list")) return nullptr;

    ast::Block *body = parseBlock();
    if (!body) return nullptr;
    fn->body = body;
    return fn;
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

    if (!expect(TokenKind::Assign, "'=' in a variable declaration")) return nullptr;

    ast::Expr *init = parseExpr();
    if (!init) return nullptr;
    if (!expect(TokenKind::Semicolon, "';' after the variable declaration"))
        return nullptr;

    return make<ast::VarDeclStmt>(loc, std::move(name), init);
}

ast::Stmt *Parser::parseAssignOrExprStatement() {
    // Assignment: IDENT '=' expr ';'  - only when '=' directly follows the name.
    if (check(TokenKind::Identifier) && peek(1).kind == TokenKind::Assign) {
        const SourceLocation loc = current().location;
        std::string name = current().spelling.str();
        advance();  // IDENT
        advance();  // '='

        ast::Expr *value = parseExpr();
        if (!value) return nullptr;
        if (!expect(TokenKind::Semicolon, "';' after the assignment"))
            return nullptr;
        return make<ast::AssignStmt>(loc, std::move(name), value);
    }

    // Otherwise: expr ';'  (covers `print(x);` and other bare calls).
    const SourceLocation loc = current().location;
    ast::Expr *e = parseExpr();
    if (!e) return nullptr;
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

// --- expressions (precedence climbing, lowest to highest) -------

ast::Expr *Parser::parseExpr() { return parseEquality(); }

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
    ast::Expr *left = parseAdditive();
    if (!left) return nullptr;
    for (;;) {
        ast::BinaryOp op;
        if (check(TokenKind::Lt)) {
            op = ast::BinaryOp::Lt;
        } else if (check(TokenKind::LtEq)) {
            op = ast::BinaryOp::Le;
        } else if (check(TokenKind::Gt)) {
            op = ast::BinaryOp::Gt;
        } else if (check(TokenKind::GtEq)) {
            op = ast::BinaryOp::Ge;
        } else {
            return left;
        }
        const SourceLocation loc = current().location;
        advance();
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
    ast::Expr *left = parseUnary();
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
        ast::Expr *right = parseUnary();
        if (!right) return nullptr;
        left = make<ast::BinaryExpr>(loc, op, left, right);
    }
}

ast::Expr *Parser::parseUnary() {
    if (check(TokenKind::Minus)) {
        const SourceLocation loc = current().location;
        advance();
        ast::Expr *operand = parseUnary();
        if (!operand) return nullptr;
        return make<ast::UnaryExpr>(loc, ast::UnaryOp::Neg, operand);
    }
    return parsePrimary();
}

ast::Expr *Parser::parsePrimary() {
    const Token &tok = current();

    switch (tok.kind) {
    case TokenKind::IntLiteral:
        advance();
        return make<ast::IntLiteralExpr>(tok.location, tok.intValue);

    case TokenKind::StringLiteral:
        advance();
        return make<ast::StringLiteralExpr>(tok.location, tok.stringValue);

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
