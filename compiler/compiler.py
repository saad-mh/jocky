#!/usr/bin/env python3
"""
compiler.py — JOCKY Language Compiler

Usage:
    python compiler.py <source.jk> [options]

Options:
    --run           JIT-execute immediately (no linker needed)
    --emit-ir       Save the LLVM IR to a .ll text file
    --no-obfuscate  Skip obfuscation passes
    -o <dir>        Output directory (default: output/)
"""

import sys
import os
import argparse
import ctypes
import subprocess
import shutil
import random
import struct

if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
if hasattr(sys.stderr, 'reconfigure'):
    sys.stderr.reconfigure(encoding='utf-8', errors='replace')

_HERE = os.path.dirname(os.path.abspath(__file__))
GCC   = shutil.which('gcc') or r'C:\mingw64\bin\gcc.exe'

try:
    import llvmlite.ir      as ir
    import llvmlite.binding as llvm
except ImportError:
    print("ERROR: llvmlite is not installed.  Run:  pip install llvmlite")
    sys.exit(1)

from jocky.lexer    import Lexer
from jocky.parser   import Parser, ParseError
from jocky.semantic import SemanticAnalyzer, SemanticError
from jocky.codegen  import CodeGenerator, CodegenError
from jocky.passes   import ObfuscationPasses, compute_hash
from jocky.stdlib   import register_all


# ── Import table variation pool ───────────────────────────────────────────────
# Each per-build entry shim imports a random subset of these "decoy" functions
# so every compiled binary has a different import table hash.

_DECOY_IMPORTS = [
    ("kernel32.dll", "GetTickCount",           "DWORD WINAPI GetTickCount(void);"),
    ("kernel32.dll", "GetSystemTimeAsFileTime","void WINAPI GetSystemTimeAsFileTime(void*);"),
    ("kernel32.dll", "Sleep",                  "void WINAPI Sleep(DWORD);"),
    ("kernel32.dll", "GetCurrentProcessId",    "DWORD WINAPI GetCurrentProcessId(void);"),
    ("kernel32.dll", "GetCurrentThreadId",     "DWORD WINAPI GetCurrentThreadId(void);"),
    ("kernel32.dll", "QueryPerformanceCounter","BOOL WINAPI QueryPerformanceCounter(void*);"),
    ("kernel32.dll", "GetCommandLineW",        "wchar_t* WINAPI GetCommandLineW(void);"),
    ("kernel32.dll", "GetModuleHandleW",       "HMODULE WINAPI GetModuleHandleW(const wchar_t*);"),
    ("kernel32.dll", "SetThreadPriority",      "BOOL WINAPI SetThreadPriority(HANDLE,int);"),
    ("kernel32.dll", "GetComputerNameW",       "BOOL WINAPI GetComputerNameW(wchar_t*,DWORD*);"),
    ("user32.dll",   "GetSystemMetrics",       "int WINAPI GetSystemMetrics(int);"),
    ("user32.dll",   "GetCursorPos",           "BOOL WINAPI GetCursorPos(void*);"),
    ("user32.dll",   "GetForegroundWindow",    "HWND WINAPI GetForegroundWindow(void);"),
    ("user32.dll",   "GetWindowTextW",         "int WINAPI GetWindowTextW(HWND,wchar_t*,int);"),
    ("user32.dll",   "FindWindowW",            "HWND WINAPI FindWindowW(const wchar_t*,const wchar_t*);"),
    ("shell32.dll",  "SHGetFolderPathW",       "HRESULT WINAPI SHGetFolderPathW(HWND,int,HANDLE,DWORD,wchar_t*);"),
    ("wininet.dll",  "InternetGetConnectedState","BOOL WINAPI InternetGetConnectedState(DWORD*,DWORD);"),
    ("ntdll.dll",    "RtlGetVersion",          "NTSTATUS NTAPI RtlGetVersion(void*);"),
    ("ntdll.dll",    "NtClose",                "NTSTATUS NTAPI NtClose(HANDLE);"),
    ("advapi32.dll", "GetUserNameW",           "BOOL WINAPI GetUserNameW(wchar_t*,DWORD*);"),
    ("advapi32.dll", "RegCloseKey",            "LONG WINAPI RegCloseKey(HKEY);"),
    ("iphlpapi.dll", "GetAdaptersInfo",        "DWORD WINAPI GetAdaptersInfo(void*,ULONG*);"),
    ("psapi.dll",    "GetModuleBaseNameW",     "DWORD WINAPI GetModuleBaseNameW(HANDLE,HMODULE,wchar_t*,DWORD);"),
    ("msvcrt.dll",   "rand",                   "int rand(void);"),
    ("msvcrt.dll",   "time",                   "long time(long*);"),
    ("ole32.dll",    "CoInitialize",           "HRESULT WINAPI CoInitialize(void*);"),
    ("gdi32.dll",    "GetDeviceCaps",          "int WINAPI GetDeviceCaps(HDC,int);"),
    ("version.dll",  "GetFileVersionInfoSizeW","DWORD WINAPI GetFileVersionInfoSizeW(const wchar_t*,DWORD*);"),
    ("wtsapi32.dll", "WTSGetActiveConsoleSessionId","DWORD WINAPI WTSGetActiveConsoleSessionId(void);"),
    ("dbghelp.dll",  "SymGetOptions",          "DWORD WINAPI SymGetOptions(void);"),
]

def _generate_import_variation_shim(base_name: str, output_dir: str) -> tuple[str, str, list[str]]:
    """
    Generate a per-build C shim that imports a random subset of decoy functions.
    Returns (c_path, o_path, extra_link_libs).
    """
    rng = random.Random(os.urandom(8))
    num_decoys = rng.randint(4, 12)
    chosen = rng.sample(_DECOY_IMPORTS, min(num_decoys, len(_DECOY_IMPORTS)))

    build_id = int.from_bytes(os.urandom(4), "little")

    lines = [
        '#include <windows.h>',
        '',
        '/* Per-build import variation — different on every compile */',
        f'static const unsigned int _build_variation_id = 0x{build_id:08X}U;',
        '',
    ]

    # Declarations
    dll_set: set[str] = set()
    for dll, func, decl in chosen:
        lines.append(f'/* {dll} */ {decl}')
        dll_set.add(dll)

    lines += [
        '',
        '/* Opaque call so the linker cannot dead-strip the imports */',
        'static volatile int _dummy = 0;',
        'static __attribute__((noinline)) void _jk_variation_init(void) {',
        f'    if (_build_variation_id == 0x{build_id ^ 0xDEAD:08X}U) {{ /* never true */ ',
    ]

    for dll, func, decl in chosen:
        # Generate a benign-looking call so the import survives link optimization
        if "void" in decl.split(func)[1].split("(")[1].split(")")[0].strip():
            lines.append(f'        {func}(0);')
        else:
            lines.append(f'        _dummy = (int)(size_t){func}(0);')

    lines += [
        '    }',
        '}',
        '',
        'extern void start(void);',
        '',
        '/* __chkstk trampoline for LLVM MSVC-triple → MinGW */',
        '__asm__(".global __chkstk\\n\\t"',
        '        "__chkstk:\\n\\t"',
        '        "jmp ___chkstk_ms\\n\\t");',
        '',
        'int main(void) {',
        '    _jk_variation_init();',
        '    start();',
        '    return 0;',
        '}',
    ]

    c_path = os.path.join(output_dir, '_jocky_entry.c')
    o_path = os.path.join(output_dir, '_jocky_entry.o')
    with open(c_path, 'w', encoding='utf-8') as f:
        f.write('\n'.join(lines) + '\n')

    # Derive -l flags for the DLLs the decoys need
    _dll_to_lib = {
        "kernel32.dll": "kernel32", "user32.dll": "user32",
        "shell32.dll":  "shell32",  "wininet.dll": "wininet",
        "ntdll.dll":    "ntdll",    "advapi32.dll": "advapi32",
        "iphlpapi.dll": "iphlpapi","psapi.dll": "psapi",
        "msvcrt.dll":   "msvcrt",  "ole32.dll": "ole32",
        "gdi32.dll":    "gdi32",   "version.dll": "version",
        "wtsapi32.dll": "wtsapi32","dbghelp.dll": "dbghelp",
    }
    extra_libs = list({f"-l{_dll_to_lib[d]}" for d in dll_set if d in _dll_to_lib})
    return c_path, o_path, extra_libs


# ── Full compilation pipeline ─────────────────────────────────────────────────

def compile_jocky(
    source_path:    str,
    output_dir:     str  = 'output',
    emit_ir:        bool = False,
    run_jit:        bool = False,
    obfuscate:      bool = True,
    obfuscate_jit:  bool = False,
) -> bool:

    print(f"\n{'='*60}")
    print(f"  JOCKY Compiler")
    print(f"  Source : {source_path}")
    mode = 'JIT' if run_jit else 'native binary (gcc)'
    print(f"  Mode   : {mode}")
    print(f"{'='*60}")

    try:
        with open(source_path, 'r', encoding='utf-8') as f:
            source = f.read()
    except FileNotFoundError:
        print(f"\nERROR: File not found: {source_path}")
        return False

    base_name = os.path.splitext(os.path.basename(source_path))[0]
    os.makedirs(output_dir, exist_ok=True)

    # Stage 1: Lexer
    print("\n[1/5] Lexer — tokenising source...")
    tokens = Lexer(source).tokenize()
    errors = [t for t in tokens if t.type.name == 'ERROR']
    if errors:
        for e in errors:
            print(f"    Line {e.line}: {e.value}")
        return False
    print(f"      OK — {len(tokens)} tokens")

    # Stage 2: Parser
    print("\n[2/5] Parser — building AST...")
    try:
        ast = Parser(tokens).parse()
    except ParseError as e:
        print(f"  Parse error: {e}")
        return False
    print(f"      OK — {len(ast.functions)} function(s)")
    if 'start' not in [f.name for f in ast.functions]:
        print("  WARNING: No 'start' function — entry point missing")

    # Stage 3: Semantic
    print("\n[3/5] Semantic analysis...")
    try:
        SemanticAnalyzer().analyze(ast)
    except SemanticError as e:
        print(f"  Semantic error:\n{e}")
        return False
    print("      OK")

    # Stage 4: IR generation
    print("\n[4/5] Generating LLVM IR...")
    try:
        ir_module = CodeGenerator(source_name=base_name).generate(ast)
    except CodegenError as e:
        print(f"  IR generation error: {e}")
        return False
    print("      OK")

    # Stage 5: Obfuscation
    if obfuscate and not run_jit:
        print("\n[5/5] Obfuscation passes (native mode)...")
        ir_module = ObfuscationPasses(ir_module, encrypt_strings=True).run_all()
        print("      OK — build-ID + string XOR + entropy + import variation")
    elif run_jit and obfuscate_jit:
        print("\n[5/5] Obfuscation passes (JIT — structural only)...")
        ir_module = ObfuscationPasses(ir_module, encrypt_strings=False).run_all()
        print("      OK — polymorphic build-ID + entropy")
    elif run_jit:
        print("\n[5/5] Obfuscation skipped (JIT mode)")
    else:
        print("\n[5/5] Obfuscation SKIPPED (--no-obfuscate)")

    ir_text = str(ir_module)
    if emit_ir:
        ir_path = os.path.join(output_dir, base_name + '.ll')
        with open(ir_path, 'w', encoding='utf-8') as f:
            f.write(ir_text)
        print(f"\n  IR file  : {ir_path}")

    llvm.initialize_native_target()
    llvm.initialize_native_asmprinter()

    try:
        llvm_mod = llvm.parse_assembly(ir_text)
        llvm_mod.verify()
    except Exception as e:
        print(f"\nERROR: IR verification failed: {e}")
        bad = os.path.join(output_dir, base_name + '_debug.ll')
        with open(bad, 'w') as f:
            f.write(ir_text)
        print(f"  Dumped bad IR to: {bad}")
        return False

    if run_jit:
        return _run_jit(llvm_mod)
    else:
        return _emit_and_link(llvm_mod, base_name, output_dir)


def _run_jit(llvm_mod) -> bool:
    print("\n  JIT execution — entry point: 'start'")
    register_all()
    target = llvm.Target.from_default_triple()
    tm     = target.create_target_machine()
    try:
        with llvm.create_mcjit_compiler(llvm_mod, tm) as engine:
            engine.finalize_object()
            engine.run_static_constructors()
            func_addr = engine.get_function_address('start')
            if func_addr == 0:
                print("  ERROR: 'start' not found")
                return False
            start_fn = ctypes.CFUNCTYPE(None)(func_addr)
            print(f"\n{'─'*40}")
            start_fn()
            print(f"{'─'*40}")
            print("\n  Execution complete.")
            return True
    except Exception as e:
        print(f"  JIT error: {e}")
        import traceback; traceback.print_exc()
        return False


def _emit_and_link(llvm_mod, base_name: str, output_dir: str) -> bool:
    target  = llvm.Target.from_default_triple()
    tm      = target.create_target_machine(opt=2, reloc='static')
    obj_bytes = tm.emit_object(llvm_mod)
    obj_path  = os.path.join(output_dir, base_name + '.o')
    with open(obj_path, 'wb') as f:
        f.write(obj_bytes)
    print(f"\n  Object file : {obj_path}")

    sha = compute_hash(obj_path)
    print(f"  SHA-256     : {sha}")
    print("  (Every compile produces a different SHA-256 — real polymorphism)")

    forensics_o = os.path.join(_HERE, 'stdlib', 'forensics.o')
    exe_path    = os.path.join(output_dir, base_name + '.exe')

    if not os.path.exists(forensics_o):
        print(f"\n  NOTE: stdlib/forensics.o not found — run build_stdlib.py first")
        return True

    if not os.path.exists(GCC):
        print(f"\n  NOTE: gcc not found at {GCC}")
        return True

    # Generate per-build import variation shim
    print("\n  Generating import table variation shim...")
    entry_c, entry_o, extra_libs = _generate_import_variation_shim(base_name, output_dir)

    r = subprocess.run(
        [GCC, '-c', entry_c, '-o', entry_o, '-O2',
         '-DWIN32_LEAN_AND_MEAN', '-D_WIN32_WINNT=0x0601'],
        capture_output=True, text=True,
    )
    if r.returncode != 0:
        print(f"  Entry shim compile error:\n{r.stderr}")
        # Fall back to minimal shim
        entry_c, entry_o = _minimal_shim(output_dir)
        extra_libs = []

    print(f"\n  Linking (import variation: {len(extra_libs)} extra DLLs)...")
    link_cmd = [
        GCC,
        obj_path, forensics_o, entry_o,
        '-o', exe_path,
        '-O2', '-mconsole',
        '-lpsapi', '-liphlpapi', '-ladvapi32',
    ] + extra_libs

    result = subprocess.run(link_cmd, capture_output=True, text=True)
    if result.returncode != 0:
        print(f"  Link error:\n{result.stderr}")
        return True

    exe_sha = compute_hash(exe_path)
    size_kb = os.path.getsize(exe_path) // 1024
    print(f"\n  Executable   : {exe_path}  ({size_kb} KB)")
    print(f"  SHA-256 (exe): {exe_sha}")
    return True


def _minimal_shim(output_dir: str) -> tuple[str, str]:
    """Fallback minimal entry shim if variation shim fails to compile."""
    c_path = os.path.join(output_dir, '_jocky_entry.c')
    o_path = os.path.join(output_dir, '_jocky_entry.o')
    with open(c_path, 'w') as f:
        f.write(
            'extern void start(void);\n'
            '__asm__(".global __chkstk\\n\\t"'
            ' "__chkstk:\\n\\t" "jmp ___chkstk_ms\\n\\t");\n'
            'int main(void){start();return 0;}\n'
        )
    return c_path, o_path


def main() -> None:
    ap = argparse.ArgumentParser(description='JOCKY Language Compiler')
    ap.add_argument('source')
    ap.add_argument('-o', '--output', default='output')
    ap.add_argument('--emit-ir',       action='store_true')
    ap.add_argument('--run',           action='store_true')
    ap.add_argument('--no-obfuscate',  action='store_true')
    ap.add_argument('--obfuscate-jit', action='store_true')
    args = ap.parse_args()
    ok = compile_jocky(
        source_path   = args.source,
        output_dir    = args.output,
        emit_ir       = args.emit_ir,
        run_jit       = args.run,
        obfuscate     = not args.no_obfuscate,
        obfuscate_jit = args.obfuscate_jit,
    )
    sys.exit(0 if ok else 1)


if __name__ == '__main__':
    main()
