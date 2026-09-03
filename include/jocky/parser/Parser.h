// The parser: a flat list of tokens in, an AST out.
//
// It is a hand-written recursive-descent parser - one method per grammar rule
// (see docs/03-language-v0.md). Like the lexer it does not throw. On a syntax
// error it reports a diagnostic, skips ahead to a likely recovery point
// (the next `;`, `}`, `func`, or end of input), and keeps parsing so more than
// one error can be found per run. The driver stops the pipeline afterwards if
// diags.hasErrors().

#ifndef JOCKY_PARSER_PARSER_H
#define JOCKY_PARSER_PARSER_H

#include "jocky/ast/AST.h"
#include "jocky/lexer/Token.h"

#include <cstddef>
#include <memory>
#include <utility>

#include <llvm/ADT/ArrayRef.h>

namespace jocky {

class DiagnosticEngine;

class Parser {
public:
    Parser(llvm::ArrayRef<Token> tokens, DiagnosticEngine &diags);

    // Parses the whole token list. Always returns a Module (possibly partial if
    // there were errors); callers check diags.hasErrors().
    std::unique_ptr<ast::Module> parseModule();

private:
    // --- grammar rules ---
    ast::FunctionDecl *parseFunctionDecl();
    ast::Block *parseBlock();
    ast::Stmt *parseStatement();
    ast::Stmt *parseVarDecl();
    ast::Stmt *parseAssignOrExprStatement();
    ast::Stmt *parseIf();
    ast::Stmt *parseWhile();
    ast::Stmt *parseReturn();

    ast::Expr *parseExpr();
    ast::Expr *parseEquality();
    ast::Expr *parseRelational();
    ast::Expr *parseAdditive();
    ast::Expr *parseMultiplicative();
    ast::Expr *parseUnary();
    ast::Expr *parsePrimary();

    // --- token cursor ---
    const Token &peek(std::size_t ahead = 0) const;
    const Token &current() const { return peek(0); }
    bool check(TokenKind kind) const { return current().kind == kind; }
    bool atEnd() const { return check(TokenKind::Eof); }
    const Token &advance();
    bool match(TokenKind kind);  // advance and return true if current kind matches
    // Consume a token of `kind` or report "expected <what>". Returns success.
    bool expect(TokenKind kind, const char *what);

    // Skip ahead after an error to a likely fresh start.
    void synchronize();
    bool tooManyErrors() const;

    // Allocate a node into the module's arena and return a typed pointer.
    template <typename T, typename... Args>
    T *make(Args &&...args) {
        auto owned = std::make_unique<T>(std::forward<Args>(args)...);
        T *raw = owned.get();
        module_->arena.push_back(std::move(owned));
        return raw;
    }

    llvm::ArrayRef<Token> tokens_;
    DiagnosticEngine &diags_;
    std::size_t pos_ = 0;
    std::unique_ptr<ast::Module> module_;
};

}  // namespace jocky

#endif  // JOCKY_PARSER_PARSER_H
