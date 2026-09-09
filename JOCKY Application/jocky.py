#!/usr/bin/env python3
"""
jocky.py — JOCKY Language CLI Wrapper

Usage:
    python jocky.py                          Open the interactive TUI
    python jocky.py run    <file.jk>         JIT-execute a script
    python jocky.py build  <file.jk>         Compile to native .exe
    python jocky.py ir     <file.jk>         Print LLVM IR (no obfuscation)
    python jocky.py ir-obf <file.jk>         Print LLVM IR (obfuscated)
    python jocky.py tokens <file.jk>         Print token list
    python jocky.py ast    <file.jk>         Print AST
    python jocky.py show   <file.jk>         Show source with line numbers
    python jocky.py inspect <file.jk>        Full pipeline summary

On Windows, call via the jocky.bat wrapper:
    jocky run scripts/proc_scanner.jk
"""

import sys
import os
import subprocess
from pathlib import Path

APP_DIR      = Path(__file__).parent.resolve()
COMPILER_DIR = APP_DIR / "compiler"
OUTPUT_DIR   = APP_DIR / "output"
OUTPUT_DIR.mkdir(exist_ok=True)

sys.path.insert(0, str(COMPILER_DIR))


# ── Colour helpers (no deps) ──────────────────────────────────────────────────

def _c(code, text):
    if os.name == "nt":
        try:
            import ctypes
            ctypes.windll.kernel32.SetConsoleMode(
                ctypes.windll.kernel32.GetStdHandle(-11), 7)
        except Exception:
            pass
    return f"\033[{code}m{text}\033[0m"

RED    = lambda t: _c("31", t)
GREEN  = lambda t: _c("32", t)
YELLOW = lambda t: _c("33", t)
CYAN   = lambda t: _c("36", t)
BOLD   = lambda t: _c("1",  t)
DIM    = lambda t: _c("2",  t)


def banner():
    print(CYAN(BOLD("=" * 60)))
    print(CYAN(BOLD("  JOCKY Language CLI")))
    print(CYAN("  Compiled Security Language — LLVM Backend"))
    print(CYAN(BOLD("=" * 60)))


def usage():
    banner()
    print(f"""
{BOLD("Commands:")}
  {CYAN("run")}     <file.jk>      JIT-execute (no linker needed)
  {CYAN("build")}   <file.jk>      Compile to native .exe
  {CYAN("ir")}      <file.jk>      Show LLVM IR (clean)
  {CYAN("ir-obf")}  <file.jk>      Show LLVM IR (obfuscated)
  {CYAN("tokens")}  <file.jk>      Show lexer tokens
  {CYAN("ast")}     <file.jk>      Show AST
  {CYAN("show")}    <file.jk>      Print source with line numbers
  {CYAN("inspect")} <file.jk>      Full pipeline summary

{BOLD("Quick start:")}
  python jocky.py run scripts/proc_scanner.jk
  python jocky.py run scripts/threat_hunter.jk
  python jocky.py ir  scripts/net_monitor.jk

{BOLD("Interactive TUI:")}
  python jocky.py
  (or: jocky.bat on Windows)
""")


# ── Import compiler modules ───────────────────────────────────────────────────

def _get_compiler_modules():
    try:
        from jocky.lexer    import Lexer
        from jocky.parser   import Parser, ParseError
        from jocky.semantic import SemanticAnalyzer, SemanticError
        from jocky.codegen  import CodeGenerator, CodegenError
        from jocky.passes   import ObfuscationPasses
        return Lexer, Parser, ParseError, SemanticAnalyzer, SemanticError, \
               CodeGenerator, CodegenError, ObfuscationPasses
    except ImportError as e:
        print(RED(f"ERROR: Cannot import JOCKY compiler: {e}"))
        print("Run setup first:  setup.bat  (Windows) or  bash setup.sh  (Linux/Mac)")
        sys.exit(1)


def _read_source(path: Path) -> str:
    if not path.exists():
        print(RED(f"ERROR: File not found: {path}"))
        sys.exit(1)
    return path.read_text(encoding="utf-8")


def _resolve(file_arg: str) -> Path:
    p = Path(file_arg)
    if p.is_absolute():
        return p
    # Try relative to cwd first, then relative to app dir
    if p.exists():
        return p.resolve()
    alt = APP_DIR / file_arg
    if alt.exists():
        return alt.resolve()
    return p.resolve()  # let the caller catch the missing file


# ── Commands ──────────────────────────────────────────────────────────────────

def cmd_run(file_arg: str):
    """JIT-execute a .jk file via the compiler subprocess."""
    path = _resolve(file_arg)
    banner()
    print(f"  {DIM('Mode:')} JIT execution")
    print(f"  {DIM('File:')} {path}\n")
    result = subprocess.run(
        [sys.executable, str(COMPILER_DIR / "compiler.py"), str(path), "--run"],
        cwd=str(COMPILER_DIR)
    )
    sys.exit(result.returncode)


def cmd_build(file_arg: str, no_obf: bool = False):
    """Compile to native .exe via gcc."""
    path = _resolve(file_arg)
    banner()
    print(f"  {DIM('Mode:')} Native binary")
    print(f"  {DIM('File:')} {path}")
    print(f"  {DIM('Out:')}  {OUTPUT_DIR}\n")
    args = [sys.executable, str(COMPILER_DIR / "compiler.py"),
            str(path), "-o", str(OUTPUT_DIR)]
    if no_obf:
        args.append("--no-obfuscate")
    result = subprocess.run(args, cwd=str(COMPILER_DIR))
    sys.exit(result.returncode)


def cmd_show(file_arg: str):
    """Print source with line numbers."""
    path = _resolve(file_arg)
    source = _read_source(path)
    banner()
    print(f"\n  {CYAN(path.name)}\n")
    for i, line in enumerate(source.splitlines(), 1):
        print(f"  {DIM(f'{i:4}')}│ {line}")
    print()


def cmd_tokens(file_arg: str):
    """Lex the file and print the token table."""
    mods = _get_compiler_modules()
    Lexer = mods[0]
    path   = _resolve(file_arg)
    source = _read_source(path)
    banner()
    print(f"\n  {CYAN('Tokens')} — {path.name}\n")

    tokens = Lexer(source).tokenize()
    errors = [t for t in tokens if t.type.name == "ERROR"]
    if errors:
        for e in errors:
            print(RED(f"  Lex error L{e.line}: {e.value}"))
        sys.exit(1)

    print(f"  {'LINE':>4}  {'COL':>3}  {'TYPE':<20}  VALUE")
    print("  " + "─" * 56)
    for tok in tokens:
        if tok.type.name == "EOF":
            continue
        color = RED if tok.type.name == "ERROR" else (lambda x: x)
        print(color(f"  {tok.line:>4}  {tok.column:>3}  {tok.type.name:<20}  {tok.value!r}"))

    print(f"\n  {DIM(f'Total: {len(tokens)} tokens')}\n")


def cmd_ast(file_arg: str):
    """Parse the file and print the AST."""
    mods = _get_compiler_modules()
    Lexer, Parser, ParseError = mods[0], mods[1], mods[2]
    path   = _resolve(file_arg)
    source = _read_source(path)
    banner()
    print(f"\n  {CYAN('AST')} — {path.name}\n")

    try:
        tokens = Lexer(source).tokenize()
        ast    = Parser(tokens).parse()
    except Exception as e:
        print(RED(f"  Error: {e}"))
        sys.exit(1)

    def _walk(node, depth=0):
        pad  = "  " + ("    " * depth)
        name = type(node).__name__

        if hasattr(node, "functions"):
            print(f"{pad}{CYAN('Program')}")
            for fn in node.functions:
                _walk(fn, depth + 1)
        elif name == "FunctionDef":
            params = ", ".join(f"{p.name}:{p.type_annotation}" for p in node.params)
            print(f"{pad}{BOLD('func')} {CYAN(node.name)}({params}) -> {node.return_type}")
            _walk(node.body, depth + 1)
        elif name == "Block":
            print(f"{pad}{DIM(f'Block [{len(node.statements)} stmt(s)]')}")
            for s in node.statements:
                _walk(s, depth + 1)
        elif name == "VarDecl":
            print(f"{pad}{YELLOW('var')} {node.name} : {node.type_annotation}")
            _walk(node.initializer, depth + 1)
        elif name == "Assignment":
            print(f"{pad}{YELLOW(node.name)} <-")
            _walk(node.value, depth + 1)
        elif name == "IfStatement":
            print(f"{pad}{BOLD('check')}")
            _walk(node.condition, depth + 1)
            print(f"{pad}  then:")
            _walk(node.then_body, depth + 2)
            if node.else_body:
                print(f"{pad}  otherwise:")
                _walk(node.else_body, depth + 2)
        elif name == "LoopStatement":
            print(f"{pad}{BOLD('loop')}")
            _walk(node.condition, depth + 1)
            _walk(node.body, depth + 1)
        elif name == "ReturnStatement":
            print(f"{pad}{BOLD('give')}" + (" ..." if node.value else ""))
            if node.value:
                _walk(node.value, depth + 1)
        elif name == "ExpressionStatement":
            _walk(node.expression, depth)
        elif name == "FunctionCall":
            print(f"{pad}{CYAN(node.name)}() [{len(node.arguments)} arg(s)]")
            for a in node.arguments:
                _walk(a, depth + 1)
        elif name == "BinaryExpression":
            print(f"{pad}BinOp [{node.operator}]")
            _walk(node.left, depth + 1)
            _walk(node.right, depth + 1)
        elif name == "UnaryExpression":
            print(f"{pad}UnaryOp [{node.operator}]")
            _walk(node.operand, depth + 1)
        elif name == "Identifier":
            print(f"{pad}{YELLOW(node.name)}")
        elif name == "NumberLiteral":
            print(f"{pad}{GREEN(str(node.value))}")
        elif name == "FloatLiteral":
            print(f"{pad}{GREEN(str(node.value))}")
        elif name == "StringLiteral":
            v = node.value[:40] + "..." if len(node.value) > 40 else node.value
            print(f"{pad}{GREEN(f'`{v}`')}")
        elif name == "BoolLiteral":
            print(f"{pad}{GREEN('yes' if node.value else 'no')}")
        elif name == "BreakStatement":
            print(f"{pad}{BOLD('stop')}")
        elif name == "SkipStatement":
            print(f"{pad}{BOLD('skip')}")
        else:
            print(f"{pad}{name}")

    _walk(ast)
    print()


def cmd_ir(file_arg: str, obfuscate: bool = False):
    """Generate and print LLVM IR."""
    mods = _get_compiler_modules()
    Lexer, Parser, ParseError, SemanticAnalyzer, SemanticError, \
        CodeGenerator, CodegenError, ObfuscationPasses = mods

    path   = _resolve(file_arg)
    source = _read_source(path)
    banner()
    label = "Obfuscated" if obfuscate else "Clean"
    print(f"\n  {CYAN(f'LLVM IR ({label})')} — {path.name}\n")

    try:
        tokens    = Lexer(source).tokenize()
        ast       = Parser(tokens).parse()
        SemanticAnalyzer().analyze(ast)
        ir_module = CodeGenerator().generate(ast)
        if obfuscate:
            ir_module = ObfuscationPasses(ir_module, encrypt_strings=True).run_all()
        ir_text = str(ir_module)
    except Exception as e:
        print(RED(f"  Error: {e}"))
        sys.exit(1)

    for line in ir_text.splitlines():
        if line.startswith("define") or line.startswith("declare"):
            print(CYAN(line))
        elif line.strip().startswith(";"):
            print(DIM(line))
        elif "=" in line and "@" in line:
            print(YELLOW(line))
        else:
            print(line)

    lines = ir_text.count("\n")
    print(f"\n  {DIM(f'{lines} lines of LLVM IR')}")
    if obfuscate:
        print(f"  {YELLOW('String globals XOR-encrypted. Unique polymorphic build ID injected.')}")
    print()


def cmd_inspect(file_arg: str):
    """Full pipeline summary."""
    mods = _get_compiler_modules()
    Lexer, Parser, ParseError, SemanticAnalyzer, SemanticError, \
        CodeGenerator, CodegenError, ObfuscationPasses = mods

    path   = _resolve(file_arg)
    source = _read_source(path)
    banner()
    print(f"\n  {CYAN('Pipeline Inspection')} — {path.name}\n")

    results = {}

    # Stage 1
    try:
        tokens = Lexer(source).tokenize()
        errs   = [t for t in tokens if t.type.name == "ERROR"]
        results["Lexer"]     = (True,  f"{len(tokens)} tokens" + (f" ({len(errs)} errors)" if errs else ""))
    except Exception as e:
        results["Lexer"]     = (False, str(e))

    # Stage 2
    try:
        ast = Parser(tokens).parse()
        results["Parser"]    = (True, f"{len(ast.functions)} function(s)")
    except Exception as e:
        results["Parser"]    = (False, str(e))
        ast = None

    # Stage 3
    if ast:
        try:
            SemanticAnalyzer().analyze(ast)
            results["Semantic"]  = (True, "no type errors")
        except Exception as e:
            results["Semantic"]  = (False, str(e)[:80])
    else:
        results["Semantic"]      = (False, "skipped (parse failed)")

    # Stage 4
    ir_module = None
    if ast:
        try:
            ir_module = CodeGenerator().generate(ast)
            ir_text   = str(ir_module)
            results["LLVM IR"]   = (True, f"{ir_text.count(chr(10))} lines")
        except Exception as e:
            results["LLVM IR"]   = (False, str(e))
    else:
        results["LLVM IR"]       = (False, "skipped")

    # Stage 5
    if ir_module:
        try:
            ob  = ObfuscationPasses(ir_module, encrypt_strings=True).run_all()
            obt = str(ob)
            results["Obfuscation"] = (True, f"{obt.count(chr(10))} lines | XOR encrypted | polymorphic")
        except Exception as e:
            results["Obfuscation"] = (False, str(e))
    else:
        results["Obfuscation"]    = (False, "skipped")

    stages = ["Lexer", "Parser", "Semantic", "LLVM IR", "Obfuscation"]
    print(f"  {'Stage':<22}  {'Status':<8}  Details")
    print("  " + "─" * 70)
    for stage in stages:
        ok, detail = results[stage]
        status = GREEN("PASS") if ok else RED("FAIL")
        print(f"  {stage:<22}  {status:<8}  {detail}")

    if ast:
        print(f"\n  {CYAN('Functions:')}")
        for fn in ast.functions:
            p = ", ".join(f"{p.name}:{p.type_annotation}" for p in fn.params)
            entry = "  ← entry point" if fn.name == "start" else ""
            print(f"    {CYAN('func')} {BOLD(fn.name)}({p}) -> {fn.return_type}{entry}")
    print()


# ── Main dispatcher ───────────────────────────────────────────────────────────

def main():
    args = sys.argv[1:]

    if not args:
        # Launch TUI
        import importlib.util
        tui = APP_DIR / "jocky_terminal.py"
        spec = importlib.util.spec_from_file_location("jocky_terminal", str(tui))
        mod  = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        mod.main_menu()
        return

    cmd = args[0].lower()

    if cmd in ("-h", "--help", "help"):
        usage()

    elif cmd == "run":
        if len(args) < 2:
            print(RED("Usage: jocky run <file.jk>"))
            sys.exit(1)
        cmd_run(args[1])

    elif cmd == "build":
        if len(args) < 2:
            print(RED("Usage: jocky build <file.jk>"))
            sys.exit(1)
        no_obf = "--no-obfuscate" in args
        cmd_build(args[1], no_obf=no_obf)

    elif cmd == "show":
        if len(args) < 2:
            print(RED("Usage: jocky show <file.jk>"))
            sys.exit(1)
        cmd_show(args[1])

    elif cmd == "tokens":
        if len(args) < 2:
            print(RED("Usage: jocky tokens <file.jk>"))
            sys.exit(1)
        cmd_tokens(args[1])

    elif cmd == "ast":
        if len(args) < 2:
            print(RED("Usage: jocky ast <file.jk>"))
            sys.exit(1)
        cmd_ast(args[1])

    elif cmd == "ir":
        if len(args) < 2:
            print(RED("Usage: jocky ir <file.jk>"))
            sys.exit(1)
        cmd_ir(args[1], obfuscate=False)

    elif cmd in ("ir-obf", "ir-obfuscated"):
        if len(args) < 2:
            print(RED("Usage: jocky ir-obf <file.jk>"))
            sys.exit(1)
        cmd_ir(args[1], obfuscate=True)

    elif cmd == "inspect":
        if len(args) < 2:
            print(RED("Usage: jocky inspect <file.jk>"))
            sys.exit(1)
        cmd_inspect(args[1])

    elif cmd.endswith(".jk"):
        # Shorthand: jocky script.jk → run it
        cmd_run(args[0])

    else:
        print(RED(f"Unknown command: {cmd}"))
        usage()
        sys.exit(1)


if __name__ == "__main__":
    main()
