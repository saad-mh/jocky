# Obfuscation Pipeline

## Why Obfuscation Is Built In

Static AV and hash-based detection work by matching known byte patterns or file hashes. A tool compiled once and distributed produces the same binary every time — one signature blocks it everywhere.

JOCKY's obfuscation is applied at the LLVM IR level before the final machine-code pass. Every compile of the same source produces a structurally different binary: different SHA-256, different import table, encrypted string constants. The obfuscation is automatic — it runs on every `jocky build` invocation, and optionally on `jocky run` with `--obfuscate`.

## The Four Passes

All passes are implemented in `compiler/jocky/passes.py` and run via `ObfuscationPasses(module, encrypt_strings).run_all()`.

---

### Pass 1 — Polymorphic Build Marker

**What it does:** Injects a 16-byte global `@_jocky_build_id` filled with cryptographically random bytes.

**Why:** This global makes the binary unique on every compile at the IR level. Even if two compilations of the same source produce identical logic, the `_jocky_build_id` bytes differ, changing the file hash and defeating simple binary-identical matching. It also serves as a build correlation tag if you need to trace which binary came from which compile run (read it at runtime with `kernel_read` or a debugger).

**IR fragment:**
```llvm
@_jocky_build_id = global [16 x i8] c"\xf3\x2a\x11..." ; 16 random bytes
```

---

### Pass 2 — String Encryption (XOR)

**What it does:** Picks a single random XOR key (1–255). Encrypts every `@.jk_str.*` string global in-place. Writes the key to the `@_jocky_xor_key` global that `codegen.py` pre-declares.

At runtime, every string reference is wrapped in a call to `jk_xordecrypt()` which reads `_jocky_xor_key` and XORs the bytes back before use. The C implementation in `forensics.c` is the actual runtime decryptor for native builds.

**Why:** Plaintext strings in a binary are the easiest static detection surface. Tool names, registry paths, API strings — all disappear from the binary. A `strings` scan or YARA rule matching on string content finds nothing.

**Why a single key instead of per-string keys:** Per-string keys would require embedding each key alongside its string — still findable. A single global key means the only way to recover strings is to run the binary or locate and read `_jocky_xor_key`. It is a deliberate trade-off: slightly weaker crypto isolation in exchange for a simpler runtime decryptor.

**JIT mode note:** In JIT mode, `stdlib.py` registers a `jk_xordecrypt` shim that is a no-op (returns the input unchanged). This is correct because strings are already plaintext in the IR at JIT time — Pass 2 encrypts the globals in-memory in the IR module object, but the JIT module is compiled and executed immediately and never serialised to disk, so the encrypted values would only be seen if you dump the IR. The shim ensures the function signature matches what `codegen.py` emits.

---

### Pass 3 — Entropy Injection

**What it does:** Injects a 64-bit global `@_jocky_entropy` filled with a random value.

**Why:** Changes the data section layout and contributes additional entropy to the binary's byte pattern. Some static analysis tools compute fuzzy hashes (e.g. ssdeep) over the data section to find near-duplicate binaries. A randomised 8-byte global shifts all subsequent data section offsets and perturbs the fuzzy hash.

**IR fragment:**
```llvm
@_jocky_entropy = global i64 7392841029384751920  ; random per build
```

---

### Pass 4 — CFG Obfuscation (Opaque Predicates)

**What it does:** For each user-defined function in the module, generates a companion "dead" function `@_jk_opcfg_N` that contains an opaque predicate: a condition that is mathematically always true (`N*(N+1) % 2 == 0` for integer N) but appears to depend on external input, followed by a conditional call to the real user function.

**Why:** Control-flow graph analysis is one of the primary techniques used by AV engines to fingerprint malware families regardless of packing or encryption. Opaque predicates add fake call-edges and branches to the CFG. A naive CFG analysis will see many more paths than actually exist and fail to match against known-malicious signatures. The real user functions are still called through the normal call graph — the dead functions are never called by the entry point, but they are present in the binary and visible to disassemblers.

**Example IR:**
```llvm
define i64 @_jk_opcfg_0(i64 %n) {
entry:
  %t0 = mul i64 %n, %n              ; n*n
  %t1 = add i64 %t0, %n             ; n*n + n = n*(n+1)
  %t2 = srem i64 %t1, 2             ; n*(n+1) % 2 — always 0
  %cond = icmp eq i64 %t2, 0        ; always true
  br i1 %cond, label %real, label %dead
real:
  %r = call i64 @start()            ; real function
  br label %exit
dead:
  br label %exit
exit:
  ret i64 0
}
```

---

## Import Variation (Native Builds Only)

In addition to the four IR passes, `compiler/compiler.py` generates a per-build **import variation shim**: a C source file that imports a random subset (4–12 chosen from 30) of Windows API functions. These imports appear in the binary's import table but are never called.

**Why:** EDR products and sandbox analysis systems fingerprint binaries by their import hash (imphash) — a hash of the imported function names in order. Randomising which decoy imports appear in every build ensures the imphash differs on every compile, even if the actual program logic is identical.

The shim also contains the `main()` C entry point that calls the `start()` symbol from the `.jk` object file, bridging the linker's expected C entry point to the JOCKY entry point convention.

## Summary Table

| Pass | Artifact | Detection Surface Targeted |
|---|---|---|
| 1 — Polymorphic marker | `_jocky_build_id` (16 random bytes) | File hash / binary identity |
| 2 — String encryption | XOR-encrypted `@.jk_str.*` globals | Static string scanning / YARA |
| 3 — Entropy injection | `_jocky_entropy` (random i64) | Fuzzy hashing of data sections |
| 4 — CFG obfuscation | Dead `_jk_opcfg_N` functions | CFG-based family fingerprinting |
| Import variation (native) | Random decoy imports in shim | Import hash (imphash) matching |

## Enabling / Disabling

```
jocky build <file>                   obfuscation ON (default)
jocky build <file> --no-obfuscate    obfuscation OFF (debug builds)
jocky run   <file> --obfuscate       JIT with obfuscation passes
jocky ir    <file>                   clean IR (no obfuscation)
jocky ir-obf <file>                  obfuscated IR
```
