# JOCKY grammar

This is the whole language as it exists today. When you add a feature, update
this file in the same change.

The L0 "type system" milestone is landing in increments; what is described here
is what the compiler actually accepts now. See `docs/requirements.md` for the
milestone plan.

## Notation

- `UPPER` - a token from the lexer (see below).
- `'x'` - a literal keyword or symbol.
- `a b` - `a` followed by `b`.
- `a | b` - `a` or `b`.
- `a?` - optional.
- `a*` - zero or more.
- `(a b)` - grouping.

## Tokens

    INT        decimal digits (`42`), or `0x` / `0X` and hex digits (`0x2A`),
               optionally followed by a type suffix `i8 i16 i32 i64 u8 u16 u32
               u64` (`42u32`). The digits must fit a signed 64-bit integer; the
               value must fit the suffix type.
    FLOAT      `1.0`, `.5`, `3.14`, `1e10`, `2.5e-3`; a trailing `f` (`3.14f`)
               makes it a `float` instead of a `double`.
    CHAR       `'A'`, one byte, with the escapes `\n \t \r \\ \' \0`.
    STRING     "..." on a single line; escapes `\n \t \r \\ \" \' \0`.
    IDENT      a letter or _, then letters, digits, or _. Type names
               (`int`, `char`, `bool`, `double`, `float`, `i8`..`i64`,
               `u8`..`u64`, `void`) are ordinary identifiers, recognised only
               in type position.
    keywords   func  var  if  else  while  return  as  true  false
    symbols    ( ) { } , : ; ->  =  + - * / %  == !=  < <= > >=

`//` starts a comment that runs to the end of the line. Whitespace separates
tokens and is otherwise ignored. `print` is **not** a keyword - it is an
ordinary identifier that codegen treats as a builtin.

## Grammar

    program      := (functionDecl | statement)*

    functionDecl := 'func' IDENT '(' paramList? ')' ('->' type)? block
    paramList    := param (',' param)*
    param        := IDENT (':' type)?          // the annotation is required
                                               // semantically; a missing one is
                                               // a sema error, not a parse error
    type         := IDENT                       // a type name; array / pointer
                                               // forms arrive in later milestones

    block        := '{' statement* '}'

    statement    := varDecl
                  | ifStmt
                  | whileStmt
                  | returnStmt
                  | block
                  | assignStmt
                  | exprStmt

    varDecl      := 'var' IDENT (':' type)? '=' expr ';'
    assignStmt   := IDENT '=' expr ';'          // chosen when '=' follows the name
    exprStmt     := expr ';'
    ifStmt       := 'if' '(' expr ')' block ('else' (block | ifStmt))?
    whileStmt    := 'while' '(' expr ')' block
    returnStmt   := 'return' expr? ';'

    expr           := equality
    equality       := relational (('==' | '!=') relational)*
    relational     := additive (('<' | '<=' | '>' | '>=') additive)*
    additive       := multiplicative (('+' | '-') multiplicative)*
    multiplicative := cast (('*' | '/' | '%') cast)*
    cast           := unary ('as' type)*
    unary          := '-' unary | primary
    primary        := INT
                    | FLOAT
                    | CHAR
                    | STRING
                    | 'true' | 'false'
                    | IDENT
                    | IDENT '(' argList? ')'    // a call
                    | '(' expr ')'
    argList        := expr (',' expr)*

Binary operators are left-associative. Precedence, lowest to highest:
`== !=`  <  `< <= > >=`  <  `+ -`  <  `* / %`  <  `as`  <  unary `-`.

## Semantics

### Types

- `int` - signed 64-bit, wraps on overflow. The default for a bare integer
  literal and for a function result with no `-> type`.
- `char` - unsigned 8-bit; also the byte type. A synonym for `u8`.
- `bool` - `true` / `false`. A comparison produces `bool`.
- `double` / `float` - IEEE-754 binary64 / binary32.
- `i8 i16 i32 i64` / `u8 u16 u32 u64` - sized integers. `u*` arithmetic,
  comparison, and `print` are unsigned. `int` is `i64`; `char` is `u8`.
- `void` - only as a function result (`-> void`).

A bare integer literal has no fixed type: it takes whatever its context needs,
as long as its value fits (so `var x: u8 = 200;` and `(0 as u64) - 1` are fine).
A literal with a suffix, and every other expression, has one definite type.

### Conversions

- **Implicit** (no cast, widening only): `char -> int`; a narrower integer to a
  wider one of the *same signedness*; `int -> double`; `float -> double`. Sema
  inserts these where a value must match a parameter, a `var`'s declared type, an
  assignment target, or a function's return type.
- **Explicit** (`expr as T`): every narrowing, any signed/unsigned
  reinterpretation, `int` <-> `float`, `double -> float`, and anything to or
  from `bool`.
- `bool` does not implicitly become a number. A bare integer expression *in a
  condition* (`if (n)`, `while (n)`) means `n != 0`; nowhere else.

### Names and functions

- Parameters are annotated; the return type defaults to `int`. A function that
  runs off the end returns the zero value of its result type (nothing for
  `void`).
- Local variables infer their type from the initializer unless annotated;
  `var x: T = e` requires `e` to be assignable to `T`.
- Functions may be called before they appear in the file. `print` takes exactly
  one argument and picks its format from the argument's type. Top-level
  statements form an implicit `main` that returns `int` (the exit code);
  declaring `main` yourself is an error.
- Strings: a string literal may still only be passed directly to `print` (a
  first-class `char[]` string arrives with arrays, L0.6/L0.7).

### Pipeline

Front end (lex + parse) -> semantic analysis (`src/sema/`, name resolution and
typing) -> codegen. `jocky check <file>.jk` runs everything up to and including
sema and stops.
