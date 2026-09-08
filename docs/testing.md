# Testing JOCKY

Tests use LLVM's own tools: **lit** (the test runner) and **FileCheck** (matches
program output against expected patterns). They are taken from the vendored LLVM
build tree (`.vendor/llvm-build/bin/`), because the installed SDK does not ship
them.

## Running the tests

    cmake --build build --target check

or, through CTest:

    ctest --test-dir build

Both run every test under `test/`.

## Kinds of test

**`test/frontend/`** - checks the compiler's output for a given program:
the token stream (`lex --dump-tokens`), the syntax tree (`parse --dump-ast`),
the generated LLVM IR (`build --emit-llvm`), or a diagnostic message. Fast; no
linker needed.

**`test/e2e/`** - compiles a `.jk` program to a real executable, runs it, and
checks what it prints. These are skipped automatically if no linker (`clang`)
was found at configure time. Each one starts with `// REQUIRES: e2e`.

## Anatomy of a test

A test is a `.jk` file. Lines starting with `// RUN:` are shell commands lit
runs in order; `// CHECK:` lines (and `CHECK-NEXT`, `CHECK-DAG`, ...) describe
what the output must contain. lit expands `%s` to the test file, `%t` to a
scratch path, and the substitutions `%jocky`, `%FileCheck`, `%not`.

Because the repository path contains spaces, always quote `"%s"` and `"%t..."`
in RUN lines.

Frontend example (`test/frontend/ir_function_call.jk`):

    // RUN: %jocky build --emit-llvm "%s" | %FileCheck "%s"

    func add(a, b) {
        return a + b;
    }

    print(add(2, 40));

    // CHECK: define i64 @add(i64 %a, i64 %b)
    // CHECK-LABEL: define i64 @main()
    // CHECK:         %[[C:[A-Za-z0-9_.]+]] = call i64 @add(i64 2, i64 40)
    // CHECK:         call i32 (ptr, ...) @printf(ptr {{.*}}, i64 %[[C]])

End-to-end example (`test/e2e/run_fib.jk`):

    // REQUIRES: e2e
    // RUN: %jocky build "%s" -o "%t.exe"
    // RUN: "%t.exe" | %FileCheck "%s"

    func fib(n) {
        check (n < 2) { return n; }
        return fib(n - 1) + fib(n - 2);
    }

    print(fib(10));

    // CHECK: 55

## Adding a test

Drop a new `.jk` file in `test/frontend/` or `test/e2e/`. lit discovers it
automatically - no list to update. Re-run `cmake --build build --target check`.
