# JOCKY grammar (v0)

This is the whole language as it exists today. When you add a feature, update
this file in the same change.

## Notation

- `UPPER` - a token from the lexer (see below).
- `'x'` - a literal keyword or symbol.
- `a b` - `a` followed by `b`.
- `a | b` - `a` or `b`.
- `a?` - optional.
- `a*` - zero or more.
- `(a b)` - grouping.

## Tokens

    INT        one or more decimal digits, e.g. 0, 42, 1000
               (must fit in a signed 64-bit integer)
    STRING     "..." on a single line; escapes: \n \t \r \\ \" \0
    IDENT      a letter or _, then letters, digits, or _
    keywords   func  var  if  else  while  return
    symbols    ( ) { } , ;  =  + - * / %  == !=  < <= > >=

`//` starts a comment that runs to the end of the line. Whitespace separates
tokens and is otherwise ignored. `print` is **not** a keyword - it is an
ordinary identifier that codegen treats as a builtin.

## Grammar

    program      := (functionDecl | statement)*

    functionDecl := 'func' IDENT '(' paramList? ')' block
    paramList    := IDENT (',' IDENT)*

    block        := '{' statement* '}'

    statement    := varDecl
                  | ifStmt
                  | whileStmt
                  | returnStmt
                  | block
                  | assignStmt
                  | exprStmt

    varDecl      := 'var' IDENT '=' expr ';'
    assignStmt   := IDENT '=' expr ';'          // chosen when '=' follows the name
    exprStmt     := expr ';'
    ifStmt       := 'if' '(' expr ')' block ('else' (block | ifStmt))?
    whileStmt    := 'while' '(' expr ')' block
    returnStmt   := 'return' expr? ';'

    expr         := equality
    equality     := relational (('==' | '!=') relational)*
    relational   := additive (('<' | '<=' | '>' | '>=') additive)*
    additive     := multiplicative (('+' | '-') multiplicative)*
    multiplicative := unary (('*' | '/' | '%') unary)*
    unary        := '-' unary | primary
    primary      := INT
                  | STRING
                  | IDENT
                  | IDENT '(' argList? ')'      // a call
                  | '(' expr ')'
    argList      := expr (',' expr)*

Binary operators are left-associative. Precedence, lowest to highest:
`== !=`  <  `< <= > >=`  <  `+ -`  <  `* /  %`  <  unary `-`.

## Semantics (v0)

- **Types.** There is one value type: a 64-bit signed integer. Arithmetic wraps
  on overflow. `/` and `%` are signed; dividing by zero is undefined.
- **Booleans.** A comparison produces 0 or 1. In an `if` or `while` condition,
  any non-zero value is true.
- **Variables.** `var` introduces a variable in the current function; it must be
  given a starting value. Assigning to a name that was never declared is an
  error. (v0 does not have nested scopes - a name is visible for the rest of the
  function.)
- **Functions.** Every parameter and every return value is a 64-bit integer;
  there are no type annotations. A function that reaches its end without
  `return` returns 0. Functions may be called before they appear in the file.
- **`main`.** Statements written at the top level (outside any function) become
  the body of an automatically created `main`. Declaring a function named `main`
  yourself is an error.
- **Strings.** A string literal may only be passed directly to `print`. It
  cannot be stored in a variable, returned, or used in an expression.
- **`print`.** Takes exactly one argument. Given an integer it prints the number
  followed by a newline; given a string literal it prints the text followed by a
  newline. As an expression, `print(x)` has the value 0.
