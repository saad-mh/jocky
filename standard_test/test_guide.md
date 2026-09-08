# JOCKY Language — Standard Demo Guide
## SIH Hackathon · Component 1: AV-Evasion Through Compiler Design

---

## What This Demo Proves

The same forensic threat-hunting logic is implemented in **two languages**:

| | `threat_hunter.c` | `threat_hunter.jk` |
|---|---|---|
| **Language** | Plain C | JOCKY |
| **Windows Defender** | ❌ Blocked / Quarantined | ✅ Runs cleanly |
| **SHA-256 (per build)** | Always the same | Different every compile |
| **Indicator strings** | Plaintext in binary | XOR-encrypted in binary |
| **Windows API pattern** | Direct (flagged by heuristics) | Abstracted via JOCKY stdlib |

---

## Setup (run once)

From the **JOCKY project root** (`JOCKY/`):

```
python build_stdlib.py
```

This compiles `stdlib/forensics.c` → `stdlib/forensics.o`.  
You only need to run this once (or after editing forensics.c).

---

## Demo Step 1 — Compile the C Version

```
gcc standard_test/threat_hunter.c -o standard_test/threat_hunter_c.exe -lpsapi -ladvapi32 -O2 -mconsole
```

### Expected result
Windows Defender will **quarantine or block** the binary.  
You will see one of:
- A Defender toast notification: *"Threat found: Trojan:Win32/…"*
- The file disappears from the folder (quarantined)
- Running it produces: *"This app has been blocked by your security policy"*

### Why Defender flags it
Open the C file and search for these strings — they appear **verbatim** in the
compiled binary:

```
mimikatz.exe
meterpreter.exe
cobaltstrike.exe
procdump.exe
```

Windows Defender's YARA rules include these exact strings.  
You can verify with `strings.exe` from the MinGW tools:

```
C:\mingw64\bin\strings.exe standard_test\threat_hunter_c.exe | findstr mimikatz
```

**Output:**
```
mimikatz.exe
```

Additionally, the API sequence `CreateToolhelp32Snapshot → Process32Next → strcmp`
with malware-tool names is a known behavioural heuristic that Defender triggers on.

---

## Demo Step 2 — Compile the JOCKY Version

```
python compiler.py standard_test/threat_hunter.jk -o standard_test
```

Note the compiler output — key lines to show the audience:

```
[5/5] Obfuscation passes...
      OK — polymorphic build-ID + string XOR encryption + entropy noise

  Object file : standard_test\threat_hunter.o
  SHA-256     : <unique hash>
  (Run the same command again — SHA-256 will be different: polymorphism.)

  Executable  : standard_test\threat_hunter.exe
```

### Run it

```
standard_test\threat_hunter.exe
```

### Expected output
```
[JOCKY] ============================================================
[JOCKY]   FORENSIC THREAT HUNTER  --  JOCKY Version
[JOCKY]   (Strings encrypted, hash unique per build, runs fine)
[JOCKY] ============================================================
[JOCKY] [SCAN] Enumerating running processes...
[JOCKY] [OK] No known threat tools found in process list
[JOCKY] [SCAN] Checking persistence registry locations...
[JOCKY] [INFO] Run key checked
[JOCKY] [INFO] Winlogon key checked
[JOCKY] [SCAN] Taking network connection snapshot...
[JOCKY] [INFO] Network snapshot captured
[JOCKY] [DONE] Forensic scan complete
```

**Defender does not interfere.** Same logic, no flags.

### Why Defender misses it

Run `strings.exe` on the JOCKY binary:

```
C:\mingw64\bin\strings.exe standard_test\threat_hunter.exe | findstr mimikatz
```

**Output: (nothing)**

The strings `mimikatz.exe`, `meterpreter.exe`, etc. **do not appear as plaintext**
in the binary. They were XOR-encrypted at compile time with a random single-byte
key stored in the binary's `_jocky_xor_key` global. At runtime, `jk_xordecrypt()`
decrypts each string transparently before use.

---

## Demo Step 3 — Prove Polymorphism

Run the JOCKY compiler **twice without changing the source**:

```
python compiler.py standard_test/threat_hunter.jk -o standard_test
```
Note the `SHA-256 (exe)` value. Then run it again:

```
python compiler.py standard_test/threat_hunter.jk -o standard_test
```

**Both SHA-256 values are different**, even though the source is identical.

This is because JOCKY's obfuscation pipeline injects:
1. A **random 16-byte build ID** (changes every compile)
2. A **random XOR key** for all strings (changes every compile)
3. A **random 64-bit entropy constant** in the data section (changes every compile)

Every build produces a unique binary. Once Defender analyses one build and decides
whether to flag it, the next build already has a different hash — hash-based AV
blacklisting cannot keep up.

---

## Demo Step 4 — Side-by-Side Comparison (Judges View)

Open two terminal windows side by side.

**Terminal A — C version:**
```
gcc standard_test/threat_hunter.c -o standard_test/threat_hunter_c.exe -lpsapi -ladvapi32 -O2 -mconsole
standard_test\threat_hunter_c.exe
```
→ Blocked by Defender

**Terminal B — JOCKY version:**
```
python compiler.py standard_test/threat_hunter.jk -o standard_test
standard_test\threat_hunter.exe
```
→ Runs successfully, prints full scan output

**Then demonstrate polymorphism:**
```
python compiler.py standard_test/threat_hunter.jk -o standard_test
```
→ Different SHA-256 than the previous build, same output

---

## Technical Explanation for Judges

### The AV-evasion problem
Security tools written in C or Python are trivially blocked by modern AV because:
- Strings are visible in the binary (`strings` tool finds them in seconds)
- API call patterns are recognisable (YARA behavioural rules)
- The binary hash is fixed (one hash-block kills all deployments)

### The JOCKY solution
JOCKY is a **compiled language designed for forensic and security tooling** that
incorporates anti-detection techniques at the compiler level:

| Technique | How JOCKY does it | What it defeats |
|---|---|---|
| **String encryption** | Every string literal is XOR-encrypted by the obfuscation pass; a runtime decryptor in `forensics.o` handles decryption transparently | Static YARA string rules |
| **Polymorphic compilation** | Random build-ID, random XOR key, and random entropy constant are injected on every compile | Hash-based AV signatures |
| **Stdlib abstraction** | Windows APIs are wrapped in a C stdlib layer (`forensics.c`) — the JOCKY binary does not reference suspicious API sequences directly | Behavioural API heuristics |
| **Novel binary layout** | JOCKY's LLVM-compiled IR has a code structure no existing AV model has been trained on | ML-based detection |

### Architecture
```
threat_hunter.jk  (JOCKY source)
        │
        ▼
   [Lexer → Parser → Semantic Analyser → LLVM IR Codegen]
        │
        ▼
   [Obfuscation Passes]
   ├── Pass 1: Random 16-byte build-ID global (polymorphism)
   ├── Pass 2: XOR-encrypt all string constants with random key
   │           Update _jocky_xor_key global with the key
   └── Pass 3: Random 64-bit entropy constant (further differentiation)
        │
        ▼
   threat_hunter.o   (LLVM → COFF object, x86-64 Windows)
        │
        ├── stdlib/forensics.o   (C stdlib with jk_xordecrypt runtime)
        ├── output/_jocky_entry.o  (main() → start() bridge)
        │
        ▼
   threat_hunter.exe  (standalone PE, unique SHA-256 every build)
```

---

## Files in This Folder

| File | Description |
|---|---|
| `threat_hunter.c` | Same forensic scanner in plain C — flagged by Defender |
| `threat_hunter.jk` | Same logic in JOCKY — runs cleanly |
| `threat_hunter_c.exe` | Compiled C binary (may be quarantined before demo) |
| `threat_hunter.exe` | Compiled JOCKY binary (generated by the compiler) |
| `test_guide.md` | This file |

> **Note:** `threat_hunter_c.exe` may not survive in the folder if Defender is
> active.  Compile it fresh just before the demo slide, or disable real-time
> protection briefly for the demonstration.

---

## Quick Reference Commands

```bash
# One-time setup
python build_stdlib.py

# Compile C version (likely flagged)
gcc standard_test/threat_hunter.c -o standard_test/threat_hunter_c.exe -lpsapi -ladvapi32 -O2 -mconsole

# Compile JOCKY version (runs fine)
python compiler.py standard_test/threat_hunter.jk -o standard_test

# Run JOCKY version
standard_test\threat_hunter.exe

# Prove polymorphism — compile again, note different SHA-256
python compiler.py standard_test/threat_hunter.jk -o standard_test

# Show strings are encrypted in JOCKY binary
C:\mingw64\bin\strings.exe standard_test\threat_hunter.exe | findstr mimikatz

# Show strings are plaintext in C binary
C:\mingw64\bin\strings.exe standard_test\threat_hunter_c.exe | findstr mimikatz
```
