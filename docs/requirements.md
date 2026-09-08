# JOCKY forensic-tooling requirements

This document specifies what JOCKY has to grow in order to host a memory
forensics tool, and what that tool must do. It is written as numbered
requirements so a change can cite the one it satisfies.

The work splits into four parts:

- **Part 1 - Language.** A real type system (this is the near-term detour),
  then the low-level and FFI primitives the tooling needs.
- **Part 2 - Runtime shim (`jockyrt`).** A small C library that hides the
  Win32/NT structs behind a flat, JOCKY-friendly API.
- **Part 3 - Forensic memory module.** The actual capability: dump process
  memory, inventory the address space, flag injected code.
- **Part 4 - Validation and non-functional constraints.**

## Reading guide

Each requirement has an id (`L0.3`, `F.5.1`, ...), a one-line statement, a
short rationale, an acceptance check that a test can assert, and the files it
touches. Priority is **MUST** (needed for a first working tool), **SHOULD**
(strongly wanted, can trail by a milestone), **LATER** (out of scope now,
recorded so the design leaves room).

Milestones are ordered by dependency: `L0 -> L1 -> L2 -> R -> F`, with `V`
running alongside from `L0` on.

## Scope

- Target platform: Windows 10/11, x64, user mode, running elevated.
- The tool reads target processes; it never writes target memory (the test
  harness is the only writer, and only to set up fixtures).
- No network, no persistence outside a caller-named output directory.

## Non-goals (recorded so the design doesn't foreclose them)

- Kernel-mode components: PPL/protected processes, DKOM, callback and SSDT
  inspection, hidden-process detection. Separate project, needs a signed
  driver.
- Linux/macOS targets (`/proc`, `process_vm_readv`, ELF). The runtime shim
  boundary is designed to make this a later port, not a rewrite.
- A growable/heap-allocated collection type, a first-class `string` type,
  generics, and a bounds-checked build mode. All **LATER**; see the end.

---

# Part 1 - Language

## Milestone L0 - Type system

JOCKY v0 has one value type (`i64`). Everything below replaces that with a
small static type system. This is the detour requested before the FFI work:
the forensic code is unpleasant to write without `char` buffers, `flag`
predicates, and `double` for entropy, and the FFI layer cannot describe a C
signature without distinct types at all.

### L0.1 - Primitive types (MUST)

Add `int`, `char`, `flag`, `double`, `float` as built-in types.

| type     | representation            | notes                                   |
|----------|---------------------------|-----------------------------------------|
| `int`    | signed 64-bit, wraps      | the default integer; every v0 program keeps its meaning |
| `char`   | **unsigned 8-bit**        | also the byte type; `char[N]` is a byte buffer |
| `flag`   | `i1` in registers, `i8` in memory | values `yes` / `no`         |
| `double` | IEEE-754 binary64         | earns its place via entropy math (`log2`) |
| `float`  | IEEE-754 binary32         | included for completeness; not on the forensic critical path |

*Rationale:* `char`-as-unsigned-byte unifies "text", "byte", and "FFI
`unsigned char`" into one type, which is what the scanner and the shim both
pass around.
*Acceptance:* a program declaring one variable of each type, assigning a
literal, and `print`ing it compiles and runs; `--emit-llvm` shows `i64`,
`i8`, `i1`/`i8`, `double`, `float` respectively.
*Touches:* `include/jocky/ast/AST.h` (a `Type` representation on every typed
node), `src/lexer/` (type keywords), `src/parser/`, new `src/sema/`,
`src/codegen/CodeGen.cpp`, `docs/grammar.md`.

### L0.2 - Fixed-width integer aliases (MUST)

Add `i8 i16 i32 i64` and `u8 u16 u32 u64` as names for sized integers.
`u*` arithmetic, comparison, shift, and `print` are unsigned. `int` is a
synonym for `i64`; `char` is a synonym for `u8`.

*Rationale:* a Win32 signature (`DWORD`, `USHORT`, `SIZE_T`) and a page
address cannot be expressed in signed-`i64`-only terms; region sizes and
addresses must compare unsigned.
*Acceptance:* `u32 x = 4000000000; print(x);` prints `4000000000`, not a
negative number; `(0 to u64) - 1` compares greater than `0`.
*Touches:* lexer, parser, `src/sema/`, `src/codegen/CodeGen.cpp`.

### L0.3 - Literals (MUST)

- Integer literals may carry a type suffix (`0u32`, `-1i8`); bare integer
  literals default to `int` and must fit their inferred type.
- Character literals: `'A'` (value 65, type `char`), with the existing string
  escapes (`'\n' '\t' '\r' '\\' '\'' '\0'`).
- Boolean literals: `yes`, `no`.
- Floating literals: `1.0`, `.5`, `3.14`, `1e10`, `2.5e-3` are `double`; a
  trailing `f` (`3.14f`) makes a `float`.
- Hexadecimal integer literals: `0x1000`, `0xDEADBEEF` (needed everywhere in
  this domain).

*Acceptance:* lexer test enumerates one of each and shows the token kind and
decoded value; a too-wide literal for its suffix is a lexing error that names
the type.
*Touches:* `src/lexer/Lexer.cpp`, `include/jocky/lexer/Token.h`,
`test/frontend/lex_*.jk`.

### L0.4 - Static typing discipline (MUST)

- Function parameters and the return type are annotated:
  `func f(a: int, b: char) -> flag { ... }`. A function with no result is
  `-> nothing` (new).
- Local variables infer their type from the initializer:
  `let n = 0;` is `int`, `let ok = yes;` is `flag`. An explicit annotation
  is allowed and then the initializer must be assignable to it:
  `let addr: u64 = 0;`.
- The implicit `main` returns `int` (its value is the process exit code).
  Declaring `main` yourself remains an error.

*Rationale:* annotated signatures keep call checking local and make the FFI
grammar (L2.1) fall out for free; inferred locals keep bodies as terse as v0.
*Acceptance:* `sema` reports "parameter 'p' needs a type", "cannot infer type
of 'x' from its initializer", and "returning `int` from a function declared
`-> flag`" each at the right source location.
*Touches:* `src/parser/`, new `src/sema/`, `include/jocky/ast/AST.h`
(`Param` gains a type; `FunctionDecl` gains a return type; `VarDeclStmt`
gains an optional annotation).

### L0.5 - Conversions and casts (MUST)

- Implicit conversions are **widening only**: `char -> int`,
  any-narrower-int -> any-wider-int of the same signedness, `int -> double`,
  `float -> double`.
- Everything else is explicit with `expr to T`: every narrowing, any
  signed/unsigned reinterpretation, `int <-> float`, `double -> float`,
  anything `-> flag` or `-> char`, and (in Part 1's later milestones)
  pointer/integer casts.
- `flag` does not implicitly convert to a number. A bare integer expression
  *in a condition position* (`check (n) { }`, `while (x) { }`) is shorthand for
  `!= 0`; nowhere else.
- Comparisons (`== != < <= > >=`) now produce `flag`, not `0`/`1`.

*Acceptance:* a table-driven `sema` test: each implicit pair compiles with no
cast, each explicit pair is an error without `to` and compiles with it, and
the emitted IR uses `sext`/`zext`/`trunc`/`sitofp`/`fptosi`/`fptrunc`/`fpext`
as appropriate.
*Touches:* `src/sema/`, `src/codegen/CodeGen.cpp`.

### L0.6 - Arrays and slices (MUST for `char`; other element types SHOULD)

Two forms, both borrow-only for now:

- **Fixed array `T[N]`** - storage, `N` a compile-time constant. `var buf:
  char[4096];` is one stack allocation of 4096 bytes. `arr[i]` indexes it
  (`i` is `int`; **no bounds check** - systems language, see L0.11).
  Array literals: `let t: int[3] = [10, 20, 30];`.
- **Slice `T[]`** - a borrowed view, represented as `{ base: ptr<T>, len:
  int }` (16 bytes). A `T[N]` decays to a `T[]` when passed to a parameter or
  assigned to a slice variable. `sub = arr[a:b]` makes a sub-slice.
  `arr.len` reads the length.

Growable / owned / heap arrays are **LATER**.

*Rationale:* `char[N]` is the buffer you hand to `ReadProcessMemory` and to
every `jockyrt` call; `char[]` is "these `n` bytes I read back", the unit the
scanner and the shim exchange when the length is only known at run time.
*Acceptance:* fill a `char[8]` in a loop, pass it to a `func h(b: char[])`,
have `h` sum `b[0..b.len)` and return the total; sub-slicing past the end is
undefined now but must be a clean error under L0.11 later.
*Touches:* `include/jocky/ast/AST.h` (array/slice type, index expr, slice
expr, array literal), parser, `src/sema/`, `src/codegen/CodeGen.cpp`
(`alloca [N x T]`, GEP, slice struct build/extract).

### L0.7 - String literals become `char` arrays (MUST)

A string literal is a `char[len + 1]`, NUL-terminated, and decays to
`char[]` or (L1) `ptr<char>`. The v0 rule "a string literal may only be
passed to `print`" is **removed**.

*Acceptance:* `let msg = "hi";` gives a `char[3]`; `msg.len` is 3; `msg[2]`
is `0`; the bytes can be passed to a `char[]` parameter.
*Touches:* `src/parser/`, `src/sema/`, `src/codegen/CodeGen.cpp`
(`internCString` already does the interning; drop the placement check in
`lowerExpr`'s `StringLiteralExpr` arm).

### L0.8 - Type-directed `print` (MUST)

`print` picks its format from the argument type: `int` -> `%lld`, unsigned ->
`%llu`, `double`/`float` -> `%g`, `char` -> the character, `flag` ->
`yes`/`no`, `char[]`/`ptr<char>` -> the string. One argument still.

*Acceptance:* one `print` per type, golden stdout via FileCheck.
*Touches:* `src/codegen/CodeGen.cpp` (`lowerCall`'s `print` arm,
`internFormat`), which today hard-codes `%lld\n` / `%s\n`
([`CodeGen.cpp:121`](../src/codegen/CodeGen.cpp)).

### L0.9 - Semantic analysis stage (MUST)

Add `src/sema/` between parser and codegen. It builds scoped symbol tables
with types, resolves every name, checks assignability and call signatures,
inserts conversion nodes at the points L0.5 allows them, and annotates every
expression with its resolved type. Codegen then lowers an
already-checked, fully-typed tree and stops doing its own name/arg checks.

*Rationale:* v0 folds a handful of checks into `CodeGen` ("every name
declared, calls pass the right count, string literal only to print",
[`architecture.md`](architecture.md) step 4). A real type system needs a
dedicated pass; leaving it in codegen would tangle inference with lowering.
*Acceptance:* `jocky check <file>.jk` (new, thin sub-command) runs
front end + sema and prints diagnostics with no codegen; `parse --dump-ast`
gains a resolved-type annotation per expression.
*Touches:* new `src/sema/` + header, `src/driver/Driver.cpp`,
`include/jocky/driver/Options.h` (`Command::Check`), `src/CMakeLists.txt`,
`test/frontend/sema_*.jk`.

### L0.10 - Grammar document rewrite (MUST)

`docs/grammar.md` is updated in the same change as the code, per its own
standing instruction. Tokens, the type grammar, annotated signatures,
`to`, literals, arrays/slices, and the revised semantics all land there.

### L0.11 - Optional bounds checking (LATER)

A `--checked` build inserts a length test before every index and slice and
calls a trap on failure. Off by default. Recorded now so slice lowering
(L0.6) keeps the length in a known place.

### L0.12 - Obfuscation passes are unaffected (MUST - regression)

The passes in `src/codegen/Obfuscation.cpp` run on lowered LLVM IR and do not
care about source types. `flatten` (state var + `switch`), `indirect`
(`ptrtoint`/indirect call), `junk` (dead `i64` instructions), `split`
(block boundaries) all stay valid.

*Acceptance:* `test/e2e/run_obfuscated*.jk` still pass; a new
`test/e2e/run_typed_obfuscated.jk` exercises `char[]`, `double`, and a struct
through `--obfuscate` and the module verifier stays clean.

---

## Milestone L1 - Low-level operations

### L1.1 - Bitwise and shift operators (MUST)

Add `&` `|` `^` `~` `<<` `>>` on integer types, with C precedence. `>>` is
arithmetic for signed, logical for unsigned.

*Rationale:* page-protection flags (`PAGE_EXECUTE_READWRITE == 0x40`), region
type masks, address alignment, and the entropy histogram are all bit work.
*Acceptance:* `0x40 & 0xF0`, `1 << 12`, `~0u32`, `(prot >> 4) & 7` each
evaluate correctly; precedence test vs `+` and comparison.
*Touches:* `include/jocky/lexer/Token.h`, `src/lexer/Lexer.cpp`,
`include/jocky/ast/AST.h` (`BinaryOp` gains the six; `UnaryOp` gains `BitNot`),
`src/parser/Parser.cpp` (new precedence tiers), `src/codegen/CodeGen.cpp`.

### L1.2 - Pointer type (MUST)

`ptr<T>` is a typed pointer; `rawptr` is an untyped byte pointer (C `void*`).
`none` is the null pointer literal. Pointers compare with `==` / `!=` and,
for ordering within one region walk, unsigned `<` / `>`.

*Acceptance:* `let p: ptr<int> = none; check (p == none) { }` compiles;
`rawptr` and `ptr<T>` require `to` to convert between each other.
*Touches:* ast/parser/sema/codegen; LLVM opaque `ptr` for all of them.

### L1.3 - Address-of and dereference (MUST)

`&lvalue` yields `ptr<T>` for a variable, array element, or struct field.
`*p` reads through a pointer; `*p = v` writes. Prefix `*` is unambiguous
(expression position) against the multiply operator.

*Acceptance:* round-trip `let x = 7; let p = &x; *p = 9; print(x);` -> `9`;
`&buf[16]` gives a pointer 16 bytes into a `char[]`.
*Touches:* ast (`AddrOfExpr`, `DerefExpr`), parser, sema, codegen
(`load`/`store` with the pointee type).

### L1.4 - Pointer arithmetic and int<->ptr casts (MUST)

`p + n` and `p - n` advance a `ptr<T>` by `n * sizeof(T)`; on `rawptr` the
step is one byte. `p - q` (same type) is an element count. `addr to
ptr<T>` and `p to u64` convert to and from an integer address.

*Rationale:* the region walk advances a cursor by `base + size`; a struct is
read by casting a buffer address to `ptr<S>`; a thread's start address
arrives as a `u64` and must become a pointer to classify it.
*Acceptance:* `(0x1000 to rawptr) + 0x40` equals `0x1040 to rawptr`;
`(base to ptr<int>) + 2` equals `(base + 8) ...`.
*Touches:* sema (scaling rule), codegen (`getelementptr`, `ptrtoint`,
`inttoptr`).

### L1.5 - `sizeof` / `offsetof` (MUST)

`sizeof(T)` and `sizeof(expr)` give the byte size as `int`; `offsetof(S,
field)` gives a field's byte offset. All compile-time constants.

*Acceptance:* `sizeof(u32) == 4`, `sizeof(char[16]) == 16`,
`offsetof(MBI, Protect)` matches the Win32 layout in a fixture.
*Touches:* parser, sema (constant folding), codegen.

### L1.6 - Struct overlay on bytes (MUST)

Given a `char[]` or a `rawptr`, `p to ptr<S>` then field access reads a
C-layout struct straight out of the buffer, no copy. Writing through it is
allowed but the forensic code only reads.

*Rationale:* PE headers (`IMAGE_DOS_HEADER`, `IMAGE_NT_HEADERS64`,
`IMAGE_SECTION_HEADER`) are parsed this way out of dumped bytes, which is how
the disk-vs-memory check (F.5.6) works without a C helper per header.
*Acceptance:* overlay `IMAGE_DOS_HEADER` on a buffer whose first bytes are
`4D 5A ...` and read `e_lfanew`; overlay past the buffer end is undefined now,
an error under L0.11.
*Touches:* sema (alignment/aliasing rules), codegen (GEP through the struct
type).

---

## Milestone L2 - FFI and linking

### L2.1 - `extern` declarations (MUST)

Declare an external C function with a full signature:

```
extern "C" OpenProcess(access: u32, inheritHandle: flag, pid: u32) -> rawptr;
extern "C" ReadProcessMemory(proc: rawptr, addr: rawptr, buf: rawptr,
                             size: u64, out read: ptr<u64>) -> flag;
```

Codegen creates an `ExternalLinkage` `llvm::Function` with the mapped type
and emits a normal call - the generalisation of `getOrDeclarePrintf`
([`CodeGen.cpp:112`](../src/codegen/CodeGen.cpp)) into
`getOrDeclareExtern(name, retTy, paramTys, isVarArg)`.

*Acceptance:* a program that `extern`-declares `GetCurrentProcessId() -> u32`
and prints it links and runs; a mismatched call (wrong arg count/type) is a
sema error.
*Touches:* ast (`ExternDecl`), parser (one rule), sema (register as a callee),
`src/codegen/CodeGen.cpp`, `docs/grammar.md`.

### L2.2 - Struct types with C layout (MUST)

`struct Name { field: T, ... }`: fields in declared order, natural alignment,
no reordering, trailing pad to the struct's alignment. Passable to `extern`
by `&s`. Matches the platform C ABI so `MEMORY_BASIC_INFORMATION` and friends
can be declared directly when a header isn't overlaid.

*Acceptance:* `sizeof` / `offsetof` for a hand-written `MEMORY_BASIC_-
INFORMATION` match `<winnt.h>`; `VirtualQueryEx(h, addr, &mbi, sizeof(mbi))`
fills it.
*Touches:* ast, parser, sema, codegen (`llvm::StructType`, `DataLayout`).

### L2.3 - Win64 calling convention correctness (MUST)

Integer/pointer args in `rcx rdx r8 r9` then stack; return in `rax`; structs
larger than 8 bytes passed by hidden pointer; `flag` as a 4-byte `int` at the
ABI boundary; varargs pass-through for `printf`-shaped externs.

*Acceptance:* a call into a tiny C test `.dll`/`.lib` with a 5-argument mixed
signature and a by-value struct return reads back the right values.
*Touches:* `src/codegen/CodeGen.cpp` (LLVM handles most of this once the
types are right; the requirement is a test that proves it).

### L2.4 - Link inputs (MUST)

`Options` gains `extraLibs` and `libSearchPaths`; `src/driver/Linker.cpp`
forwards them to the `clang` invocation (which today is a fixed `clang obj -o
exe -fuse-ld=lld`, [`Linker.cpp`](../src/driver/Linker.cpp)). Surface them as
`-l` / `-L` on the `jocky build` command and as a `link "name"` pragma in
source. `kernel32` is picked up automatically for `*-windows-msvc`;
`ntdll.lib` and `dbghelp.lib` must be added explicitly.

*Acceptance:* `jocky build tool.jk -l ntdll -o tool.exe` resolves
`NtQueryInformationProcess`; the pragma form does the same with no CLI flag.
*Touches:* `include/jocky/driver/Options.h`, `src/driver/main.cpp`,
`src/driver/Linker.cpp`, ast/parser (pragma), `docs/grammar.md`.

### L2.5 - Manifest embedding (SHOULD)

`jocky build --manifest requireAdministrator` (and a default-on for a
forensic profile) embeds an application manifest requesting elevation.

*Acceptance:* the produced `.exe` prompts for elevation / fails fast when run
unelevated.
*Touches:* `src/driver/Linker.cpp` (pass a `.manifest` or use
`/MANIFESTUAC`), `Options.h`.

### L2.6 - UTF-16 interop for `*W` APIs (SHOULD)

A `wstr` literal `L"..."` producing a `u16[N]` (NUL-terminated), and helpers
`utf8_to_utf16` / `utf16_to_utf8` over slices. Most useful Win32/NT calls
here are the `W` variants (`QueryFullProcessImageNameW`, module paths).

*Acceptance:* open a process by name where the name has a non-ASCII
character; round-trip a path through both helpers.
*Touches:* lexer (literal), a small runtime helper (may live in `jockyrt`),
sema/codegen.

### L2.7 - Error status surfaced (MUST)

`extern "C" GetLastError() -> u32;` works, and a `jockyrt` helper returns the
last `NTSTATUS` for the NT-family calls. Win32 APIs signal failure by return
value plus this; the scanner must distinguish "region unreadable" from
"region absent".

*Acceptance:* a deliberately failing `ReadProcessMemory` reports
`ERROR_PARTIAL_COPY` and the scanner records the region as unreadable, not
missing.
*Touches:* nothing new beyond L2.1; this is a test + a documented pattern.

---

# Part 2 - Runtime shim (`jockyrt`)

A C (or C++ compiled to a C ABI) static library, linked into every forensic
build. It exists so the Win32/NT structs, handle lifetimes, and Unicode
paths stay out of JOCKY. New tree: `runtime/jockyrt/`.

### R.1 - Flat ABI contract (MUST)

No C `struct` crosses the boundary. Every `jkf_*` function takes only
scalars (`int`, `u32`, `u64`, `flag`) and caller-owned byte buffers
(`rawptr` + length). Records written into caller buffers are fixed-size,
fixed-layout, documented in `runtime/jockyrt/abi.md`, and versioned by a
leading `u32` version field. Return convention: `>= 0` is a count or a
handle-ish token, `< 0` is `-(error code)`.

*Rationale:* keeps the language surface added in Part 1 to the minimum that's
independently useful, and makes a Linux port a second implementation of this
same header.
*Acceptance:* `abi.md` lists every record with field offsets; a C test and a
JOCKY test both parse the same bytes and agree.

### R.2 - Process enumeration (MUST)

`jkf_processes(out: rawptr, cap: u64) -> int` fills `out` with
`{ version, pid, ppid, sessionId, flags }` records (flags: is-wow64,
is-protected, elevated-unknown) and returns the count; `-E2BIG` if `cap` is
too small, with the needed count in a side call.

*Acceptance:* count matches `Get-Process`; the current pid appears with the
right `ppid`.

### R.3 - Target open / close / privilege (MUST)

`jkf_open(pid, want_write: flag) -> handle` (write always `no` in
production), `jkf_close(handle)`, `jkf_enable_debug_privilege() -> flag`.
`jkf_open` reports, via an out-param record, the access level actually
granted so the scanner can note "queried headers only, could not read".

*Acceptance:* opening a normal same-user process succeeds; opening a
system-owned one succeeds only after `jkf_enable_debug_privilege` and
elevation; opening a PPL process fails cleanly with a distinct code.

### R.4 - Region walk (MUST)

`jkf_region_at(handle, addr: u64, out: rawptr) -> int` writes one
`{ version, base, size, state, type, protect, allocProtect, allocBase }`
record for the region containing (or next after) `addr`, and returns `1`, or
`0` at end of address space. The caller loops, advancing `addr = base +
size`.

*Acceptance:* the walk over the current process visits a strictly increasing,
gap-free sequence of `[base, base+size)` covering the full user range; the
image region for `jockyrt`'s own module shows `type == MEM_IMAGE`.

### R.5 - Read target memory (MUST)

`jkf_read(handle, addr: u64, buf: rawptr, len: u64) -> int` returns bytes
read (may be `< len` on a partial read), `-EFAULT` on a wholly unreadable
range. Internally chunked (default 1 MiB), skips `PAGE_GUARD` /
`PAGE_NOACCESS`, never faults the caller.

*Acceptance:* reading a committed `.data` page returns its bytes; reading a
reserved-not-committed range returns `-EFAULT`; reading a range straddling a
guard page returns the readable prefix length.

### R.6 - Module list (MUST)

`jkf_modules(handle, out: rawptr, names: rawptr, ...) -> int` returns loader
(PEB `Ldr`) modules as `{ version, base, size, entryPoint, nameOff, pathOff,
flags }` plus a packed UTF-8 name/path blob. A separate
`jkf_mapped_name(handle, addr, names, cap)` gives the backing file of an
arbitrary mapped address (for regions not in the loader list).

*Acceptance:* every `MEM_IMAGE` region's base matches a module entry, except
deliberately injected ones (fixture); `ntdll.dll` appears with a correct
path.

### R.7 - Thread enumeration (MUST)

`jkf_threads(pid, out: rawptr, cap) -> int` returns `{ version, tid,
startAddr, teb, flags }`. `startAddr` is the Win32 start address
(`NtQueryInformationThread(ThreadQuerySetWin32StartAddress)`).

*Acceptance:* the main thread's `startAddr` lands inside the main module's
`.text`; an injected `CreateRemoteThread` fixture shows a `startAddr` outside
every module.

### R.8 - Coherent snapshot (SHOULD)

`jkf_snapshot(pid) -> handle` via `PssCaptureSnapshot`, so a large process
can be inventoried and read from a frozen view. Same `jkf_region_at` /
`jkf_read` work against a snapshot handle.

*Acceptance:* inventorying a process that is actively allocating/freeing
gives a stable region list against a snapshot and a changing one without.

### R.9 - Dump container (MUST)

`jkf_dump_open_write(path) -> handle`, `jkf_dump_put(handle, base, size,
meta, buf, len)`, `jkf_dump_close`, and the read side. Format spec in
`runtime/jockyrt/dump-format.md`: a header (magic, version, target pid,
image name, timestamp), a region table (the R.4 records), then raw blobs.
Deliberately simple so the JOCKY scanner can re-open a dump for offline
analysis. Full-fidelity minidump output is **LATER**.

*Acceptance:* dump a process, reopen it, and reproduce the region inventory
byte-for-byte from the file with the target gone.

---

# Part 3 - Forensic memory module

JOCKY source under `forensic/mem/`, compiled with the forensic profile
(links `jockyrt`, `ntdll`, `dbghelp`; manifest requests elevation).
Eligible for `--obfuscate` (V.9).

### F.1 - Command surface (MUST)

```
jocky-mem inventory <pid|name> [--json]
jocky-mem scan      <pid|name> [--json] [--min-severity low|med|high]
jocky-mem dump      <pid|name> [--out DIR] [--full | --region ADDR
                               | --module NAME | --thread TID]
jocky-mem scan-dump <dump-file> [...]
```

`scan` = `inventory` + heuristics + report. `scan-dump` runs the same
heuristics that don't need a live handle against a container from R.9.

### F.2 - Full process dump (MUST)

Iterate committed, non-guard regions; `jkf_read` each; write to an R.9
container with the region table and a `manifest.json` (target, time, tool
version, per-region read status).

*Acceptance:* dump size equals the sum of committed readable region sizes
plus header; unreadable regions appear in the table marked, with no blob.

### F.3 - Targeted dump (MUST)

`--region` dumps one region; `--module` dumps that module's mapped range;
`--thread` dumps a window (default +/-64 KiB) around a thread's start
address.

*Acceptance:* `--module ntdll.dll` produces a blob whose first bytes are
`MZ` and whose size matches the module's `SizeOfImage`.

### F.4 - Region inventory (MUST)

A table of every committed region: base, size, state, type, protection,
backing file (or `-`), owning module (or `-`), and a class:
`image` / `mapped-data` / `private-data` / `private-exec` / `image-exec` /
`stack` / `heap` / `teb-peb` / `unknown`.

*Acceptance:* golden table for a known trivial target via FileCheck, sorted
by base, stable across runs.

### F.5 - Injection heuristics (MUST)

Each fires a **finding** with a reason code, the region, a confidence, and a
short evidence string. Ranked roughly by signal quality.

#### F.5.1 - RWX / write-then-exec private memory (MUST)

Committed `MEM_PRIVATE` with `PAGE_EXECUTE_READWRITE`, or whose
`AllocationProtect` was writable and current `Protect` is executable.
*Acceptance:* a fixture that `VirtualAllocEx(PAGE_EXECUTE_READWRITE)` +
`WriteProcessMemory` a NOP sled into a child is flagged on exactly that
region, confidence high.

#### F.5.2 - Executable private, unbacked (MUST)

Committed, executable, `MEM_PRIVATE`, not in any module range. Cross-checked
against the JIT allowlist (F.10).
*Acceptance:* a manual-map fixture (copy a DLL's sections into private RX
memory, no loader entry) is flagged; a .NET process is not (allowlisted).

#### F.5.3 - Executable mapped, data-backed (MUST)

Executable `MEM_MAPPED` whose backing file is a non-image file, or
pagefile-backed (no name). Module-stomping / section injection.
*Acceptance:* a fixture that maps a `.txt` as an image-like section and marks
it `+x` is flagged.

#### F.5.4 - PE signature off the module list (MUST)

Scan region starts and page-aligned offsets for `MZ` + a valid `e_lfanew` ->
`PE\0\0`; if the base is not a loader module, flag it.
*Acceptance:* a reflectively loaded DLL (no `LdrLoadDll`) is flagged with its
detected `SizeOfImage`.

#### F.5.5 - Loader list vs region set mismatch (MUST)

Diff PEB `Ldr` (all three lists, also against each other) against the
`MEM_IMAGE` region set. A region with no entry -> unlinked module; an entry
with a wrong base/size -> tampered.
*Acceptance:* a fixture that unlinks its own module from the InLoadOrder list
is flagged; the three-list cross-check catches an entry present in only two.

#### F.5.6 - Image text differs from disk (SHOULD)

For each `MEM_IMAGE` region, read the file from disk, apply relocations for
the loaded base, and diff executable sections. Differences beyond IAT
thunks / legit hotpatch -> hollowed or patched. Cheap proxy when the file is
unavailable: page-hash the in-memory `.text` and compare to the baseline DB
(F.9).
*Acceptance:* a process-hollowing fixture (`CreateProcess` suspended,
unmap, write a different image, resume) is flagged on the main module.

#### F.5.7 - Thread start address anomaly (MUST)

Map each thread's `startAddr` (R.7) to a region. Outside every module, or in
private/mapped RX memory -> injected/hijacked thread.
*Acceptance:* a `CreateRemoteThread` fixture and a thread-hijack fixture
(`SetThreadContext` to shellcode) are both flagged; normal worker threads in
a thread-pool process are not.

#### F.5.8 - Hook detection (SHOULD)

IAT thunks resolving outside the exporting module; EAT entries pointing into
private memory; the first bytes of well-known `ntdll` APIs being
`E9`/`FF25`/`push+ret` that leave the module. Compare against a clean `ntdll`
read from disk.
*Acceptance:* an inline hook on `ntdll!NtProtectVirtualMemory` installed by a
fixture is reported with the destination region.

#### F.5.9 - Executable region entropy (SHOULD)

Shannon entropy (needs `double`) over each executable region's bytes; a high
value in a private executable region corroborates F.5.1/F.5.2 (packed or
encrypted stage). Entropy alone is only a corroborator, never a sole
finding.
*Acceptance:* an XOR-encoded shellcode blob raises the region's entropy above
the configured threshold; a normal `.text` section does not.

#### F.5.10 - Small corroborators (MUST)

Single-page executable region (hook trampoline); executable region
immediately adjacent to a module's `.text` end (code cave). Low weight on
their own.
*Acceptance:* a one-page detour stub written past a module's `.text` raises
at least a low-severity finding.

### F.6 - Scoring and severity (MUST)

Each finding has a weight; a region's score is the weighted sum; severity =
`low` / `med` / `high` by configurable thresholds. `--min-severity` filters
output. A region with two independent mid heuristics outranks one weak one.

*Acceptance:* a documented weight table; a fixture matrix asserts the
severity for each single-heuristic and each common pair.

### F.7 - Artifact carving (MUST)

For every finding at or above `med`, write the region's bytes and any carved
embedded PE (headers fixed up to a raw file layout) to
`<out>/artifacts/<pid>-<base>.bin` for downstream YARA / disassembly.

*Acceptance:* the carved PE from a reflective-DLL fixture is a file a
standard PE parser opens.

### F.8 - Reporting (MUST)

Human-readable: the F.4 table with a verdict column, then a findings section
per suspicious region with a 16-byte hex preview and (SHOULD) a short x64
disassembly. Machine-readable: JSONL, one object per finding, plus a summary
object. Exit code = max severity (`0` none, `1` low/med, `2` high).

*Acceptance:* JSONL validates against a schema in `forensic/mem/report.schema.json`;
the human and JSON outputs agree on counts and severities.

### F.9 - Baseline hash DB (SHOULD)

`jocky-mem baseline build` walks the clean host's system modules and stores
per-`.text`-page hashes; `scan` consults it for F.5.6's cheap path and to
suppress known-good pages.

*Acceptance:* on a clean machine, `scan` of every system process produces no
`high` findings with a fresh baseline.

### F.10 - JIT / known-good allowlist (MUST)

A shipped, user-extendable list of processes and module patterns whose
private executable memory is expected: .NET (`clr.dll`/`coreclr.dll`), JVM,
V8/Node, PowerShell, ScriptControl, browser renderers. Allowlisted regions
still appear in the inventory, tagged, but don't raise findings on F.5.2
alone.

*Acceptance:* scanning `powershell.exe`, `dotnet.exe`, and `node.exe` at
idle yields no findings above `low`; removing an entry makes the
corresponding region light up.

---

# Part 4 - Validation and non-functional

### V.1 - Fixture-driven detection tests (MUST)

A `test/forensic/` harness that builds small C fixture targets, has the
harness (not the tool) perform each injection technique against a spawned
child, runs `jocky-mem scan --json`, and asserts the exact region and
reason code. One fixture per F.5.x sub-requirement.

### V.2 - False-positive corpus (MUST)

Spawn .NET, JVM, Node, and PowerShell at idle and under light load; assert
no finding above `low`. Gate CI on it.

### V.3 - Golden output (MUST)

FileCheck over `inventory` and `scan` text output for a trivial fixed
target; sorted, stable, no addresses that vary run to run outside clearly
marked columns.

### V.4 - Performance (SHOULD)

On the reference box, `inventory` + all MUST heuristics over a target with a
2 GiB working set completes in < 10 s; `dump --full` sustains >= 500 MiB/s to
a local disk. Numbers recorded in `docs/` and tracked, not asserted hard.

### V.5 - Obfuscation compatibility (MUST)

`forensic/mem/*.jk` compiles clean through `jocky build --obfuscate`; the
module verifier passes; a fixed `--obf-seed` is reproducible; behaviour is
identical to the non-obfuscated build on the V.1 matrix.
`src/codegen/Obfuscation.cpp` requires no change (see L0.12).

### V.6 - Determinism (MUST)

Every `jkf_*` call that returns a list returns it in a defined order
(ascending address / pid / tid). Two `scan` runs of an unchanged target
produce identical JSONL modulo the timestamp field.

### V.7 - Safety (MUST)

The production build links `jkf_open` with `want_write = no` wired to a
compile-time constant; a build that could write target memory is a separate,
test-only profile. No socket API is linked. All output stays under the
caller's `--out` directory.

### V.8 - Privilege behaviour (MUST)

Unelevated: the tool runs, inventories the current user's own processes, and
clearly reports which targets and which data (e.g. full reads) were
unavailable rather than failing opaquely.

---

# Deferred (LATER) - recorded so the design leaves room

- Growable / heap-allocated arrays and a first-class `string`; the slice
  representation in L0.6 is the seam.
- `--checked` bounds-checked builds (L0.11).
- x64 disassembly for the report and for "does not decode as sane code"
  (F.8, F.5.9).
- Full-fidelity minidump output alongside the R.9 container.
- In-process YARA over carved artifacts.
- Kernel-mode driver: protected processes, DKOM, hidden processes, kernel
  callbacks, IRP hooks.
- Linux/macOS targets - a second implementation of the `jockyrt` header
  (`process_vm_readv`, `/proc/<pid>/maps`, ELF).

# Open decisions (need sign-off before L0 starts)

1. `int` is 64-bit (keeps every v0 program valid). Confirm rather than
   matching C's 32-bit `int`.
2. `char` is unsigned 8-bit and doubles as the byte type. Confirm vs. a
   separate `byte`/`u8` with `char` reserved for text.
3. Typing discipline: annotated signatures, inferred locals. Confirm vs.
   full annotations everywhere or full inference.
4. Slices (`T[]` as base+len) are in for L0; growable arrays are LATER.
   Confirm the split.
5. Runtime shim language: C. Confirm vs. C++ or Zig behind the same C ABI.
6. Dump container: a custom simple format now, minidump LATER. Confirm.
7. Whether any C `struct` is ever allowed across the FFI boundary, or the
   flat-ABI rule (R.1) is absolute.
