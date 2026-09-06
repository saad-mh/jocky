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
    keywords   func  var  if  else  while  return  as  true  false  null
               sizeof  offsetof  struct
    symbols    ( ) { } [ ] . , : ; ->  =  + - * / %  & | ^ ~
               == !=  < <= > >=   (`<<` / `>>` are two adjacent `<` / `>`)

`//` starts a comment that runs to the end of the line. Whitespace separates
tokens and is otherwise ignored. `print` is **not** a keyword - it is an
ordinary identifier that codegen treats as a builtin.

## Grammar

    program      := (structDecl | functionDecl | statement)*

    structDecl   := 'struct' IDENT '{' (IDENT ':' type ','?)* '}'
                                               // fields in declared order, C
                                               // natural alignment, no reorder

    functionDecl := 'func' IDENT '(' paramList? ')' ('->' type)? block
    paramList    := param (',' param)*
    param        := IDENT (':' type)?          // the annotation is required
                                               // semantically; a missing one is
                                               // a sema error, not a parse error
    type         := ('ptr' '<' type '>' | IDENT) ('[' expr ']' | '[' ']')*
                                               // IDENT is a type name (incl.
                                               // `rawptr`); `ptr<T>` is a typed
                                               // pointer; `[expr]` a fixed array
                                               // (expr folds to a constant),
                                               // `[]` a slice

    block        := '{' statement* '}'

    statement    := varDecl
                  | ifStmt
                  | whileStmt
                  | returnStmt
                  | block
                  | assignStmt
                  | exprStmt

    varDecl      := 'var' IDENT (':' type)? ('=' expr)? ';'
                                               // the initializer may be omitted
                                               // only when a type is given
    assignStmt   := lvalue '=' expr ';'        // chosen when '=' follows a full
                                               // expression; lvalue is a name or
                                               // an index
    exprStmt     := expr ';'
    ifStmt       := 'if' '(' expr ')' block ('else' (block | ifStmt))?
    whileStmt    := 'while' '(' expr ')' block
    returnStmt   := 'return' expr? ';'

    expr           := bitOr
    bitOr          := bitXor ('|' bitXor)*
    bitXor         := bitAnd ('^' bitAnd)*
    bitAnd         := equality ('&' equality)*
    equality       := relational (('==' | '!=') relational)*
    relational     := shift (('<' | '<=' | '>' | '>=') shift)*
    shift          := additive (('<<' | '>>') additive)*
    additive       := multiplicative (('+' | '-') multiplicative)*
    multiplicative := cast (('*' | '/' | '%') cast)*
    cast           := unary ('as' type)*
    unary          := ('-' | '~' | '&' | '*') unary | postfix
                                               // prefix `&` is address-of,
                                               // prefix `*` is dereference
    postfix        := primary ('[' expr ']' | '[' expr? ':' expr? ']' | '.' IDENT)*
                                               // element index, sub-slice, `.len`
    primary        := INT
                    | FLOAT
                    | CHAR
                    | STRING
                    | 'true' | 'false' | 'null'
                    | 'sizeof' '(' (type | expr) ')'   // compile-time int
                    | 'offsetof' '(' IDENT ',' IDENT ')'  // compile-time int
                    | '[' (expr (',' expr)*)? ']'   // an array literal
                    | IDENT
                    | IDENT '(' argList? ')'    // a call
                    | '(' expr ')'
    argList        := expr (',' expr)*

Binary operators are left-associative. Precedence, lowest to highest:
`|`  <  `^`  <  `&`  <  `== !=`  <  `< <= > >=`  <  `<< >>`  <  `+ -`  <
`* / %`  <  `as`  <  unary `- ~ & *`  <  postfix `[]` / `.`.

`<<` and `>>` are never lexed as one token - they are two adjacent `<` / `>` -
so a nested `ptr<ptr<int>>` closes without a special rule.

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
- `T[N]` - a fixed array: `N` contiguous `T`s, `N` a compile-time constant.
  `arr[i]` indexes it (no bounds check), `arr.len` is `N`, `[a, b, c]` is a
  literal. `var buf: T[N];` allocates without initializing.
- `T[]` - a slice: a borrowed `{ base, len }` view. A `T[N]` becomes a `T[]`
  when passed or assigned where a slice is wanted; `arr[a:b]` makes a sub-slice
  (either bound may be omitted). `s.len` is the element count. A slice variable
  must be initialized.
- `ptr<T>` - a typed pointer. `&lvalue` makes one; `*p` reads or writes through
  it (`*p = v`). `null` is the null pointer and fits any pointer type. Pointers
  compare with `== !=` and, unsigned, with `< <= > >=`.
- `rawptr` - an untyped byte pointer (C `void*`). It cannot be dereferenced;
  cast it to a `ptr<T>` first. `rawptr` and `ptr<T>` convert only with `as`.

Pointer arithmetic: `p + n` / `p - n` move a `ptr<T>` by `n * sizeof(T)` (by
`n` bytes for a `rawptr`); `p - q` (same pointer type) is the element count
between them. `addr as ptr<T>` and `p as u64` convert between a pointer and an
integer address. `sizeof(T)` / `sizeof(expr)` is the C-layout byte size, a
compile-time `int` (`sizeof(u32)` is 4, `sizeof(char[16])` is 16,
`sizeof(ptr<T>)` is 8).

### Structs

- `struct Name { field: T, ... }` declares a record with C natural alignment:
  fields keep declared order, each is aligned to its own alignment, the struct's
  alignment is its widest field's, and its size is padded to that. A field of
  `void` type, a duplicate field or struct name, and a by-value self-reference
  (use `ptr<Name>`) are errors.
- `s.field` reads or writes a field (an lvalue); `&s` and `&s.field` take its
  address. Whole-struct assignment (`a = b`, same struct type) copies.
- A `ptr<S>` auto-dereferences for field access, so a struct can be overlaid on
  a byte buffer: `var h = buf as ptr<Header>; h.field`. An array or slice `as` a
  pointer yields its base address.
- `offsetof(S, field)` is the field's byte offset, a compile-time `int`.

A string literal is a `char[len + 1]`, NUL-terminated, and decays to `char[]`
like any other array.

A bare integer literal has no fixed type: it takes whatever its context needs,
as long as its value fits (so `var x: u8 = 200;` and `(0 as u64) - 1` are fine).
A literal with a suffix, and every other expression, has one definite type.

### Operators

- Arithmetic `+ - * / %` and the bitwise `& | ^` follow the same operand rule:
  both sides must be numbers (integers for `%` and the bitwise ops), a bare
  literal adapts to the other side, and the result is their common type.
- `~` needs an integer; `-` needs a number; each keeps the operand's type.
- `<< >>` take an integer value and an integer count (of any width - the count
  is brought to the value's type). The result is the value's type. `>>` is
  arithmetic (sign-extending) for a signed value, logical for an unsigned one.
- Comparisons `== != < <= > >=` produce `bool`.

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
  one argument and picks its format from the argument's type (a `char[N]` /
  `char[]` prints as a string). Top-level statements form an implicit `main`
  that returns `int` (the exit code); declaring `main` yourself is an error.

### Pipeline

Front end (lex + parse) -> semantic analysis (`src/sema/`, name resolution and
typing) -> codegen. `jocky check <file>.jk` runs everything up to and including
sema and stops.
