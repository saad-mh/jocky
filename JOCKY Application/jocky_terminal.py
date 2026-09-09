#!/usr/bin/env python3
"""
jocky_terminal.py — Interactive Terminal Application for the JOCKY Language.

Provides a rich TUI for running pre-built cybersecurity scripts, writing custom
JOCKY code, inspecting the compilation pipeline (tokens / AST / IR), and
building native binaries — all from one menu-driven interface.

Run:
    python jocky_terminal.py
"""

import os
import sys
import io
import subprocess
import textwrap
from pathlib import Path
from contextlib import redirect_stdout, redirect_stderr

# ── Resolve paths ─────────────────────────────────────────────────────────────
APP_DIR       = Path(__file__).parent.resolve()
COMPILER_DIR  = APP_DIR / "compiler"
SCRIPTS_DIR   = APP_DIR / "scripts"
WORKSPACE_DIR = APP_DIR / "workspace"
OUTPUT_DIR    = APP_DIR / "output"

OUTPUT_DIR.mkdir(exist_ok=True)
WORKSPACE_DIR.mkdir(exist_ok=True)

sys.path.insert(0, str(COMPILER_DIR))

# ── Rich import with graceful fallback ────────────────────────────────────────
try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich.syntax import Syntax
    from rich.prompt import Prompt
    from rich.text import Text
    from rich.rule import Rule
    from rich.align import Align
    from rich import box
    RICH = True
except ImportError:
    RICH = False

console = Console() if RICH else None


# ─────────────────────────────────────────────────────────────────────────────
# Utility helpers
# ─────────────────────────────────────────────────────────────────────────────

def clear():
    os.system("cls" if os.name == "nt" else "clear")


def pause(msg="Press Enter to continue..."):
    input(f"\n  {msg}")


def cprint(text, style=""):
    if RICH:
        console.print(text, style=style, markup=True)
    else:
        print(text)


def rprint(text):
    """Print with Rich markup (no-op fallback strips markup tags roughly)."""
    if RICH:
        console.print(text, markup=True)
    else:
        import re
        print(re.sub(r'\[/?[^\]]+\]', '', text))


def print_header(title, subtitle=""):
    if RICH:
        console.print()
        inner = f"[bold cyan]{title}[/bold cyan]"
        if subtitle:
            inner += f"\n[dim]{subtitle}[/dim]"
        console.print(Panel(Align.center(Text.from_markup(inner)),
                            border_style="cyan", padding=(1, 4)))
    else:
        print("\n" + "=" * 62)
        print(f"  {title}")
        if subtitle:
            print(f"  {subtitle}")
        print("=" * 62)


def print_section(title):
    if RICH:
        console.print()
        console.print(Rule(f"[bold yellow]{title}[/bold yellow]", style="yellow"))
    else:
        print(f"\n── {title} " + "─" * max(0, 54 - len(title)))


def _item(n, label, dim_label=""):
    """Print a numbered menu item consistently in both Rich and plain mode."""
    if RICH:
        dim_part = f"  [dim]{dim_label}[/dim]" if dim_label else ""
        console.print(f"  [bold yellow]{n:>2}.[/bold yellow]  {label}{dim_part}",
                      markup=True)
    else:
        suffix = f"  {dim_label}" if dim_label else ""
        print(f"  [{n}] {label}{suffix}")


def _item_key(key, label):
    """Print a letter-key menu item."""
    if RICH:
        console.print(f"  [bold yellow] {key}.[/bold yellow]  {label}", markup=True)
    else:
        print(f"  [{key}] {label}")


def _divider():
    if RICH:
        console.print()
    else:
        print()


def ask(prompt_text="Choice"):
    if RICH:
        console.print()
        return Prompt.ask(f"[bold green]  {prompt_text}[/bold green]").strip()
    else:
        return input(f"\n  {prompt_text}: ").strip()


# ─────────────────────────────────────────────────────────────────────────────
# Compiler integration
# ─────────────────────────────────────────────────────────────────────────────

def _import_compiler():
    try:
        from jocky.lexer    import Lexer
        from jocky.parser   import Parser, ParseError
        from jocky.semantic import SemanticAnalyzer, SemanticError
        from jocky.codegen  import CodeGenerator, CodegenError
        from jocky.passes   import ObfuscationPasses
        return Lexer, Parser, ParseError, SemanticAnalyzer, SemanticError, \
               CodeGenerator, CodegenError, ObfuscationPasses
    except ImportError as e:
        rprint(f"[red]ERROR: Could not import JOCKY compiler: {e}[/red]")
        return None


def run_jit(script_path: str, obfuscate: bool = False):
    """JIT-execute a .jk file, capturing and displaying output."""
    try:
        cmd = [sys.executable, str(COMPILER_DIR / "compiler.py"), str(script_path), "--run"]
        if obfuscate:
            cmd.append("--obfuscate-jit")
        result = subprocess.run(
            cmd,
            capture_output=True, text=True, cwd=str(COMPILER_DIR),
            env={**os.environ, "PYTHONUTF8": "1", "PYTHONIOENCODING": "utf-8"},
        )
        return result.stdout + result.stderr, result.returncode
    except Exception as e:
        return f"Error launching compiler: {e}", 1


def get_tokens(source: str):
    mods = _import_compiler()
    if not mods:
        return None, "Import failed"
    try:
        return mods[0](source).tokenize(), None
    except Exception as e:
        return None, str(e)


def get_ast(source: str):
    mods = _import_compiler()
    if not mods:
        return None, "Import failed"
    Lexer, Parser, ParseError = mods[0], mods[1], mods[2]
    try:
        return Parser(Lexer(source).tokenize()).parse(), None
    except Exception as e:
        return None, str(e)


def get_ir(source: str, obfuscate=False):
    mods = _import_compiler()
    if not mods:
        return None, "Import failed"
    Lexer, Parser, _, SemanticAnalyzer, _, CodeGenerator, _, ObfuscationPasses = mods
    try:
        tokens = Lexer(source).tokenize()
        errors = [t for t in tokens if t.type.name == "ERROR"]
        if errors:
            return None, f"Lex errors: {[e.value for e in errors]}"
        ast = Parser(tokens).parse()
        SemanticAnalyzer().analyze(ast)
        mod = CodeGenerator().generate(ast)
        if obfuscate:
            mod = ObfuscationPasses(mod, encrypt_strings=True).run_all()
        return str(mod), None
    except Exception as e:
        return None, str(e)


# ─────────────────────────────────────────────────────────────────────────────
# Script metadata
# ─────────────────────────────────────────────────────────────────────────────

BUILTIN_SCRIPTS = [
    {
        "file": "proc_scanner.jk",
        "name": "Process Scanner",
        "desc": "Enumerate all running processes and flag malicious/sensitive ones",
        "category": "Process Analysis",
        "tags": ["forensics", "malware-detection"],
    },
    {
        "file": "net_monitor.jk",
        "name": "Network Monitor",
        "desc": "Capture active TCP/UDP connections, detect C2 and exfiltration",
        "category": "Network Analysis",
        "tags": ["network", "c2-detection"],
    },
    {
        "file": "net_logger.jk",
        "name": "Network Logger",
        "desc": "Repeated connection snapshots with delta tracking",
        "category": "Network Analysis",
        "tags": ["network", "logging"],
    },
    {
        "file": "packet_sniffer.jk",
        "name": "Packet Sniffer",
        "desc": "Passive packet capture with process-based correlation",
        "category": "Network Analysis",
        "tags": ["network", "packet-capture"],
    },
    {
        "file": "resource_monitor.jk",
        "name": "Resource Monitor",
        "desc": "Risk-scored scan for miners, RATs, and lateral-movement tools",
        "category": "Resource Analysis",
        "tags": ["monitoring", "crypto-miner-detection"],
    },
    {
        "file": "sys_info.jk",
        "name": "System Info Collector",
        "desc": "Forensic triage: enumerate processes, read OS registry, snapshot network",
        "category": "System Forensics",
        "tags": ["forensics", "triage"],
    },
    {
        "file": "file_hasher.jk",
        "name": "File Integrity Checker",
        "desc": "SHA-256 hash critical system binaries, cross-reference with process list",
        "category": "File Forensics",
        "tags": ["integrity", "hash"],
    },
    {
        "file": "registry_inspector.jk",
        "name": "Registry Inspector",
        "desc": "Check Winlogon/Defender/LSA registry keys for tampering",
        "category": "Persistence Detection",
        "tags": ["registry", "persistence"],
    },
    {
        "file": "threat_hunter.jk",
        "name": "Threat Hunter  (Full Suite)",
        "desc": "Process + registry + network + file threat hunt with scored verdict",
        "category": "Threat Hunting",
        "tags": ["all-in-one", "threat-hunting"],
    },
]


# ─────────────────────────────────────────────────────────────────────────────
# AST pretty-printer
# ─────────────────────────────────────────────────────────────────────────────

def ast_to_lines(node, indent=0):
    lines = []
    prefix = "  " * indent
    name = type(node).__name__

    if hasattr(node, 'functions'):
        lines.append(f"{prefix}Program")
        for fn in node.functions:
            lines.extend(ast_to_lines(fn, indent + 1))
    elif name == 'FunctionDef':
        params = ", ".join(f"{p.name}:{p.type_annotation}" for p in node.params)
        lines.append(f"{prefix}FunctionDef  {node.name}({params}) -> {node.return_type}")
        lines.extend(ast_to_lines(node.body, indent + 1))
    elif name == 'Block':
        lines.append(f"{prefix}Block [{len(node.statements)} stmt(s)]")
        for stmt in node.statements:
            lines.extend(ast_to_lines(stmt, indent + 1))
    elif name == 'VarDecl':
        lines.append(f"{prefix}VarDecl  {node.name} : {node.type_annotation}")
        lines.extend(ast_to_lines(node.initializer, indent + 1))
    elif name == 'Assignment':
        lines.append(f"{prefix}Assign  {node.name} <-")
        lines.extend(ast_to_lines(node.value, indent + 1))
    elif name == 'IfStatement':
        lines.append(f"{prefix}If")
        lines.extend(ast_to_lines(node.condition, indent + 1))
        lines.append(f"{prefix}  Then:")
        lines.extend(ast_to_lines(node.then_body, indent + 2))
        if node.else_body:
            lines.append(f"{prefix}  Else:")
            lines.extend(ast_to_lines(node.else_body, indent + 2))
    elif name == 'LoopStatement':
        lines.append(f"{prefix}Loop")
        lines.extend(ast_to_lines(node.condition, indent + 1))
        lines.extend(ast_to_lines(node.body, indent + 1))
    elif name == 'ReturnStatement':
        lines.append(f"{prefix}Return")
        if node.value is not None:
            lines.extend(ast_to_lines(node.value, indent + 1))
    elif name == 'ExpressionStatement':
        lines.extend(ast_to_lines(node.expression, indent))
    elif name == 'FunctionCall':
        args = f" [{len(node.arguments)} arg(s)]" if node.arguments else ""
        lines.append(f"{prefix}Call  {node.name}(){args}")
        for arg in node.arguments:
            lines.extend(ast_to_lines(arg, indent + 1))
    elif name == 'BinaryExpression':
        lines.append(f"{prefix}BinOp  [{node.operator}]")
        lines.extend(ast_to_lines(node.left, indent + 1))
        lines.extend(ast_to_lines(node.right, indent + 1))
    elif name == 'UnaryExpression':
        lines.append(f"{prefix}UnaryOp  [{node.operator}]")
        lines.extend(ast_to_lines(node.operand, indent + 1))
    elif name == 'Identifier':
        lines.append(f"{prefix}Identifier  {node.name}")
    elif name == 'NumberLiteral':
        lines.append(f"{prefix}Number  {node.value}")
    elif name == 'FloatLiteral':
        lines.append(f"{prefix}Float  {node.value}")
    elif name == 'StringLiteral':
        val = node.value[:30] + "..." if len(node.value) > 30 else node.value
        lines.append(f"{prefix}String  `{val}`")
    elif name == 'BoolLiteral':
        lines.append(f"{prefix}Bool  {'yes' if node.value else 'no'}")
    elif name == 'BreakStatement':
        lines.append(f"{prefix}Break (stop)")
    elif name == 'SkipStatement':
        lines.append(f"{prefix}Skip (continue)")
    else:
        lines.append(f"{prefix}{name}")
    return lines


# ─────────────────────────────────────────────────────────────────────────────
# Shared script-action sub-menu
# ─────────────────────────────────────────────────────────────────────────────

def _script_action_menu(script_path: Path, name: str, desc: str = "",
                        category: str = "", tags: list = None,
                        allow_edit: bool = False):
    """
    Sub-menu shown after selecting any script (pre-built or custom).
    allow_edit adds an 'Edit in editor' option for workspace scripts.
    """
    while True:
        clear()
        print_header(name, desc)

        if RICH:
            if category:
                console.print(f"\n  [cyan]Category:[/cyan] {category}")
            if tags:
                console.print(f"  [cyan]Tags:[/cyan] {', '.join(tags)}")
            console.print(f"  [cyan]File:[/cyan] {script_path}")
        else:
            print(f"\n  File: {script_path}")

        _divider()
        rprint("  [bold yellow]Actions[/bold yellow]")
        _item(1, "Run  (JIT, clean)")
        _item(2, "Run  (JIT + Obfuscation)",
              "build-ID + entropy injected, SHA-256 changes every run")
        _item(3, "View Source Code")
        if allow_edit:
            _item(4, "Edit in Editor")
            _item(5, "Inspect  →  Tokens")
            _item(6, "Inspect  →  AST")
            _item(7, "Inspect  →  LLVM IR  (clean)")
            _item(8, "Inspect  →  LLVM IR  (obfuscated)")
            _item(9, "Pipeline Summary  (all stages)")
        else:
            _item(4, "Inspect  →  Tokens")
            _item(5, "Inspect  →  AST")
            _item(6, "Inspect  →  LLVM IR  (clean)")
            _item(7, "Inspect  →  LLVM IR  (obfuscated)")
            _item(8, "Pipeline Summary  (all stages)")
        _divider()
        _item(0, "Back")

        choice = ask("Action")

        if choice == "0":
            return
        elif choice == "1":
            _run_script(script_path, obfuscate=False)
        elif choice == "2":
            _run_script(script_path, obfuscate=True)
        elif choice == "3":
            _show_source(script_path)
        elif allow_edit and choice == "4":
            _open_editor(script_path)
        else:
            # offset=1 for allow_edit (Edit takes slot 4), offset=0 otherwise
            offset = 1 if allow_edit else 0
            if choice == str(4 + offset):
                _show_tokens(script_path)
            elif choice == str(5 + offset):
                _show_ast(script_path)
            elif choice == str(6 + offset):
                _show_ir(script_path, obfuscate=False)
            elif choice == str(7 + offset):
                _show_ir(script_path, obfuscate=True)
            elif choice == str(8 + offset):
                source = script_path.read_text(encoding="utf-8")
                _show_summary(script_path, source)


# ─────────────────────────────────────────────────────────────────────────────
# Menu: Pre-built Scripts
# ─────────────────────────────────────────────────────────────────────────────

def menu_prebuilt_scripts():
    while True:
        clear()
        print_header("Pre-built Cybersecurity Scripts",
                     "Battle-tested JOCKY forensics scripts")

        if RICH:
            table = Table(box=box.ROUNDED, border_style="cyan", show_header=True,
                          header_style="bold cyan", expand=True)
            table.add_column("#",        style="bold yellow", width=4)
            table.add_column("Name",     style="bold white",  min_width=24)
            table.add_column("Category", style="cyan",        min_width=18)
            table.add_column("Description", style="dim white")
            for idx, s in enumerate(BUILTIN_SCRIPTS, 1):
                table.add_row(str(idx), s["name"], s["category"], s["desc"])
            console.print(table)
        else:
            print(f"\n  {'#':<4}  {'Name':<28}  Description")
            print("  " + "─" * 70)
            for idx, s in enumerate(BUILTIN_SCRIPTS, 1):
                print(f"  {idx:<4}  {s['name']:<28}  {s['desc']}")

        _divider()
        rprint("  [dim]Enter number to select  |  0 to go back[/dim]")

        choice = ask("Select script")
        if choice == "0":
            return
        try:
            idx = int(choice) - 1
            if 0 <= idx < len(BUILTIN_SCRIPTS):
                s = BUILTIN_SCRIPTS[idx]
                _script_action_menu(
                    SCRIPTS_DIR / s["file"],
                    s["name"], s["desc"], s["category"], s["tags"],
                    allow_edit=False,
                )
            else:
                rprint(f"[red]  Enter 1–{len(BUILTIN_SCRIPTS)} or 0.[/red]")
                pause()
        except ValueError:
            rprint("[red]  Enter a number.[/red]")
            pause()


# ─────────────────────────────────────────────────────────────────────────────
# Menu: Custom Script Editor
# ─────────────────────────────────────────────────────────────────────────────

def menu_custom_script():
    while True:
        clear()
        print_header("Custom Script Editor",
                     "Write, save, and run your own JOCKY code")

        wk_scripts = sorted(WORKSPACE_DIR.glob("*.jk"))

        if RICH:
            if wk_scripts:
                rprint("\n  [bold cyan]Workspace Scripts[/bold cyan]")
                for i, p in enumerate(wk_scripts, 1):
                    size_kb = p.stat().st_size // 1024 or "<1"
                    rprint(f"  [bold yellow]{i:>2}.[/bold yellow]"
                           f"  [white]{p.name}[/white]"
                           f"  [dim]{size_kb} KB[/dim]")
            else:
                rprint("\n  [dim]  No workspace scripts yet. Press N to create one.[/dim]")
        else:
            print("\n  Workspace Scripts:")
            if wk_scripts:
                for i, p in enumerate(wk_scripts, 1):
                    print(f"  [{i:>2}] {p.name}")
            else:
                print("  (none yet — press N to create one)")

        _divider()
        rprint("  [bold yellow]Options[/bold yellow]")
        _item_key("N", "New Script")
        _item(0, "Back")

        if wk_scripts:
            rprint("  [dim]  — or enter a script number to open it[/dim]")

        choice = ask("Choice").lower()

        if choice == "0":
            return
        elif choice == "n":
            _new_script()
        else:
            try:
                idx = int(choice) - 1
                if 0 <= idx < len(wk_scripts):
                    p = wk_scripts[idx]
                    _script_action_menu(
                        p, p.name, f"Workspace script: {p}",
                        allow_edit=True,
                    )
                else:
                    rprint(f"[red]  Enter 1–{len(wk_scripts)}, N, or 0.[/red]")
                    pause()
            except ValueError:
                rprint("[red]  Enter a script number, N to create, or 0 to go back.[/red]")
                pause()


def _new_script():
    clear()
    print_header("New Script", "Create a new JOCKY script in workspace/")

    name = ask("Script name (without .jk)")
    if not name:
        return
    if not name.endswith(".jk"):
        name += ".jk"

    script_path = WORKSPACE_DIR / name
    if script_path.exists():
        rprint(f"\n  [yellow]File already exists: {script_path}[/yellow]")
        ow = ask("Overwrite? (y/n)")
        if ow.lower() != "y":
            return

    template = textwrap.dedent(f"""\
        ## {name} — JOCKY script
        ## Entry point must be:  func start() -> nothing {{ ... }}

        func start() -> nothing {{
            report(`Hello from {name}!`)
        }}
    """)
    script_path.write_text(template, encoding="utf-8")

    rprint(f"\n  [green]Created:[/green] {script_path}")
    rprint(f"  Run it with:  [cyan]jocky run workspace/{name}[/cyan]")

    _open_editor(script_path)


def _open_editor(path: Path):
    rprint(f"\n  [dim]Opening {path.name} in editor...[/dim]")
    try:
        if os.name == "nt":
            os.startfile(str(path))
        else:
            editor = os.environ.get("EDITOR", "nano")
            subprocess.run([editor, str(path)])
        rprint("  [dim]Editor launched. Save your file, then return here to run it.[/dim]")
    except Exception:
        rprint(f"  [yellow]Could not open editor. Open manually:[/yellow]  {path}")
    pause()


# ─────────────────────────────────────────────────────────────────────────────
# Menu: Script Inspector
# ─────────────────────────────────────────────────────────────────────────────

def menu_inspect():
    while True:
        clear()
        print_header("Script Inspector", "Tokens · AST · LLVM IR · Obfuscation")

        wk_scripts = sorted(WORKSPACE_DIR.glob("*.jk"))
        all_scripts = []   # (display_name, Path)

        if RICH:
            rprint("\n  [bold cyan]Pre-built Scripts[/bold cyan]")
        else:
            print("\n  Pre-built Scripts:")

        for s in BUILTIN_SCRIPTS:
            p = SCRIPTS_DIR / s["file"]
            all_scripts.append((s["name"], p))
            _item(len(all_scripts), s["name"], s["category"])

        if wk_scripts:
            _divider()
            rprint("  [bold cyan]Workspace Scripts[/bold cyan]") if RICH \
                else print("  Workspace Scripts:")
            for p in wk_scripts:
                all_scripts.append((p.name, p))
                _item(len(all_scripts), p.name)

        _divider()
        _item(0, "Back")
        rprint("  [dim]Enter number to inspect[/dim]") if RICH \
            else print("  Enter number to inspect:")

        choice = ask("Select script")
        if choice == "0":
            return
        try:
            idx = int(choice) - 1
            if 0 <= idx < len(all_scripts):
                name, path = all_scripts[idx]
                _full_inspect(path)
            else:
                rprint(f"[red]  Enter 1–{len(all_scripts)} or 0.[/red]")
                pause()
        except ValueError:
            rprint("[red]  Enter a number.[/red]")
            pause()


def _full_inspect(script_path: Path):
    source = script_path.read_text(encoding="utf-8")

    while True:
        clear()
        print_header(f"Inspect: {script_path.name}", "JOCKY Compilation Pipeline")

        _item(1, "Source Code")
        _item(2, "Tokens          (Lexer output)")
        _item(3, "AST             (Parser output)")
        _item(4, "LLVM IR         (unobfuscated)")
        _item(5, "LLVM IR         (obfuscated — XOR strings)")
        _item(6, "Pipeline Summary  (all 5 stages)")
        _divider()
        _item(0, "Back")

        choice = ask("View")

        if choice == "0":
            return
        elif choice == "1":
            _show_source(script_path)
        elif choice == "2":
            _show_tokens(script_path)
        elif choice == "3":
            _show_ast(script_path)
        elif choice == "4":
            _show_ir(script_path, obfuscate=False)
        elif choice == "5":
            _show_ir(script_path, obfuscate=True)
        elif choice == "6":
            _show_summary(script_path, source)


# ─────────────────────────────────────────────────────────────────────────────
# Menu: Build Native Binary
# ─────────────────────────────────────────────────────────────────────────────

def menu_build():
    while True:
        clear()
        print_header("Build Native Binary", "Compile .jk to a standalone Windows .exe")

        wk_scripts = sorted(WORKSPACE_DIR.glob("*.jk"))
        all_scripts = []

        if RICH:
            rprint("\n  [bold cyan]Pre-built Scripts[/bold cyan]")
        else:
            print("\n  Pre-built Scripts:")

        for s in BUILTIN_SCRIPTS:
            p = SCRIPTS_DIR / s["file"]
            all_scripts.append((s["name"], p))
            _item(len(all_scripts), s["name"], s["category"])

        if wk_scripts:
            _divider()
            rprint("  [bold cyan]Workspace Scripts[/bold cyan]") if RICH \
                else print("  Workspace Scripts:")
            for p in wk_scripts:
                all_scripts.append((p.name, p))
                _item(len(all_scripts), p.name)

        _divider()
        rprint("  [dim yellow]Requirements: MinGW gcc on PATH  |  run setup.bat once[/dim yellow]")
        _item(0, "Back")

        choice = ask("Select script to build")
        if choice == "0":
            return
        try:
            idx = int(choice) - 1
            if 0 <= idx < len(all_scripts):
                name, path = all_scripts[idx]
                _build_mode_menu(path)
            else:
                rprint(f"[red]  Enter 1–{len(all_scripts)} or 0.[/red]")
                pause()
        except ValueError:
            rprint("[red]  Enter a number.[/red]")
            pause()


def _build_mode_menu(script_path: Path):
    """Ask for obfuscation mode then build."""
    clear()
    print_header(f"Build: {script_path.name}", "Compile to standalone Windows .exe")

    if RICH:
        console.print(f"\n  [cyan]File:[/cyan] {script_path}")
    _divider()
    rprint("  [bold yellow]Build Mode[/bold yellow]")
    _item(1, "Obfuscated  (recommended)",
          "XOR-encrypted strings + polymorphic build-ID + entropy")
    _item(2, "Debug  (no obfuscation)",
          "readable IR, fixed SHA-256 — use for development")
    _divider()
    _item(0, "Back")

    choice = ask("Build mode")
    if choice == "1":
        _build_script(script_path, obfuscate=True)
    elif choice == "2":
        _build_script(script_path, obfuscate=False)


def _build_script(script_path: Path, obfuscate: bool = True):
    mode_label = "Obfuscated" if obfuscate else "Debug (no obfuscation)"
    clear()
    print_section(f"Building — {script_path.name}  [{mode_label}]")
    rprint(f"\n  [dim]Output directory: {OUTPUT_DIR}[/dim]")

    cmd = [sys.executable, str(COMPILER_DIR / "compiler.py"),
           str(script_path), "-o", str(OUTPUT_DIR)]
    if not obfuscate:
        cmd.append("--no-obfuscate")

    result = subprocess.run(
        cmd,
        capture_output=True, text=True, cwd=str(COMPILER_DIR),
        env={**os.environ, "PYTHONUTF8": "1", "PYTHONIOENCODING": "utf-8"},
    )
    output = result.stdout + result.stderr

    if RICH:
        console.print()
        style = "green" if result.returncode == 0 else "red"
        obf_tag = " [yellow](obfuscated)[/yellow]" if obfuscate else " [dim](debug)[/dim]"
        console.print(Panel(output.strip() or "(no output)",
                            border_style=style,
                            title=f"[{style}]Build Output[/{style}]{obf_tag}"))
    else:
        print("\n" + "─" * 62)
        print(output)
        print("─" * 62)
    pause()


# ─────────────────────────────────────────────────────────────────────────────
# Script viewers
# ─────────────────────────────────────────────────────────────────────────────

def _show_source(script_path: Path):
    clear()
    print_section(f"Source — {script_path.name}")
    source = script_path.read_text(encoding="utf-8")
    if RICH:
        console.print(Panel(
            Syntax(source, "text", theme="monokai", line_numbers=True, word_wrap=True),
            border_style="blue", title=f"[cyan]{script_path.name}[/cyan]"
        ))
    else:
        for i, line in enumerate(source.splitlines(), 1):
            print(f"{i:4}  {line}")
    pause()


def _show_tokens(script_path: Path):
    clear()
    print_section(f"Tokens — {script_path.name}")
    source = script_path.read_text(encoding="utf-8")
    tokens, err = get_tokens(source)

    if err:
        rprint(f"[red]Error: {err}[/red]")
        pause()
        return

    if RICH:
        table = Table(box=box.SIMPLE, border_style="blue", header_style="bold cyan")
        table.add_column("Line",  style="yellow", width=5)
        table.add_column("Col",   style="dim",    width=4)
        table.add_column("Type",  style="cyan",   min_width=16)
        table.add_column("Value", style="white")
        for tok in tokens:
            if tok.type.name == "EOF":
                continue
            color = "red" if tok.type.name == "ERROR" else "white"
            table.add_row(str(tok.line), str(tok.column), tok.type.name,
                          f"[{color}]{tok.value!r}[/{color}]")
        console.print(table)
        console.print(f"\n  [dim]Total: {len(tokens)} tokens[/dim]")
    else:
        print(f"{'LINE':>4}  {'COL':>3}  {'TYPE':<18}  VALUE")
        print("─" * 62)
        for tok in tokens:
            if tok.type.name == "EOF":
                continue
            print(f"{tok.line:>4}  {tok.column:>3}  {tok.type.name:<18}  {tok.value!r}")
        print(f"\nTotal: {len(tokens)} tokens")
    pause()


def _show_ast(script_path: Path):
    clear()
    print_section(f"AST — {script_path.name}")
    source = script_path.read_text(encoding="utf-8")
    ast, err = get_ast(source)

    if err:
        rprint(f"[red]Error: {err}[/red]")
        pause()
        return

    lines = ast_to_lines(ast)
    if RICH:
        console.print(Panel("\n".join(lines), border_style="green",
                            title="[green]Abstract Syntax Tree[/green]"))
        console.print(f"\n  [dim]Functions: {len(ast.functions)}[/dim]")
        for fn in ast.functions:
            p = ", ".join(f"{p.name}:{p.type_annotation}" for p in fn.params)
            console.print(f"    [cyan]func {fn.name}[/cyan]({p}) -> {fn.return_type}")
    else:
        for line in lines:
            print(line)
    pause()


def _show_ir(script_path: Path, obfuscate: bool):
    label = "Obfuscated" if obfuscate else "Clean"
    clear()
    print_section(f"LLVM IR ({label}) — {script_path.name}")
    source = script_path.read_text(encoding="utf-8")
    ir_text, err = get_ir(source, obfuscate=obfuscate)

    if err:
        rprint(f"[red]Error: {err}[/red]")
        pause()
        return

    if RICH:
        console.print(Panel(
            Syntax(ir_text, "llvm", theme="monokai", line_numbers=True, word_wrap=False),
            border_style="magenta",
            title=f"[magenta]LLVM IR — {label}[/magenta]"
        ))
        console.print(f"\n  [dim]{ir_text.count(chr(10))} lines  |  {len(ir_text)} chars[/dim]")
        if obfuscate:
            console.print("  [yellow]String globals XOR-encrypted."
                          " SHA-256 changes on every compile.[/yellow]")
    else:
        print(ir_text[:5000])
        if len(ir_text) > 5000:
            print(f"\n... ({len(ir_text) - 5000} more chars)")
    pause()


def _show_summary(script_path: Path, source: str):
    clear()
    print_header(f"Pipeline Summary — {script_path.name}",
                 "All 5 compilation stages")

    tokens, _ = get_tokens(source)
    ast,    _  = get_ast(source)
    ir_cl,  _  = get_ir(source, obfuscate=False)
    ir_ob,  _  = get_ir(source, obfuscate=True)

    if RICH:
        table = Table(box=box.ROUNDED, border_style="cyan", show_header=True,
                      header_style="bold cyan", expand=True)
        table.add_column("Stage",   style="bold white", min_width=24)
        table.add_column("Status",  style="bold",       width=8)
        table.add_column("Details", style="dim white")

        def _row(stage, ok, detail):
            status = "[green]PASS[/green]" if ok else "[red]FAIL[/red]"
            table.add_row(stage, status, detail)

        _row("1. Lexer  (tokenise)",
             tokens is not None,
             f"{len(tokens)} tokens" if tokens else "—")
        _row("2. Parser  (AST)",
             ast is not None,
             f"{len(ast.functions)} function(s)" if ast else "—")
        _row("3. Semantic Analysis",
             ir_cl is not None,
             "type-checked" if ir_cl else "—")
        _row("4. LLVM IR Generation",
             ir_cl is not None,
             f"{ir_cl.count(chr(10))} IR lines" if ir_cl else "—")
        _row("5. Obfuscation Pass",
             ir_ob is not None,
             f"{ir_ob.count(chr(10))} IR lines  |  XOR + polymorphic ID" if ir_ob else "—")
        console.print(table)

        if ast:
            console.print("\n  [bold cyan]Functions:[/bold cyan]")
            for fn in ast.functions:
                p = ", ".join(f"{p.name}:{p.type_annotation}" for p in fn.params)
                console.print(f"    [cyan]func {fn.name}[/cyan]({p}) -> {fn.return_type}")
    else:
        rows = [
            ("1. Lexer",          tokens, f"{len(tokens) if tokens else 0} tokens"),
            ("2. Parser (AST)",   ast,    f"{len(ast.functions) if ast else 0} func(s)"),
            ("3. Semantic",       ir_cl,  "ok"),
            ("4. LLVM IR",        ir_cl,  f"{ir_cl.count(chr(10)) if ir_cl else 0} lines"),
            ("5. Obfuscation",    ir_ob,  "XOR encrypted"),
        ]
        for stage, ok, detail in rows:
            print(f"  {stage:<24}  {'PASS' if ok else 'FAIL':<6}  {detail}")
    pause()


def _run_script(script_path: Path, obfuscate: bool = False):
    clear()
    mode_label = "JIT + Obfuscation  (structural)" if obfuscate else "JIT  (clean)"
    print_section(f"Running — {script_path.name}  [{mode_label}]")

    if obfuscate:
        rprint("\n  [dim]Applying structural obfuscation: build-ID + entropy injected.[/dim]")
        rprint("  [dim]Note: string XOR requires native build (--no-obfuscate is JIT-only limitation).[/dim]")

    rprint("\n  [dim]Compiling and executing via LLVM JIT...[/dim]")

    output, rc = run_jit(str(script_path), obfuscate=obfuscate)

    if RICH:
        console.print()
        style = "green" if rc == 0 else "red"
        obf_tag = " [yellow](obfuscated build)[/yellow]" if obfuscate else ""
        title = f"[{style}]Output[/{style}]{obf_tag}"
        console.print(Panel(output.strip() or "(no output)",
                            border_style=style, title=title))
        if rc == 0:
            if obfuscate:
                console.print("  [green]Execution complete.[/green]  "
                              "[yellow]Polymorphic build-ID injected — IR hash differs from clean run.[/yellow]")
            else:
                console.print("  [green]Execution complete.[/green]")
        else:
            console.print(f"  [red]Exit code: {rc}[/red]")
    else:
        print("\n" + "─" * 62)
        print(output)
        print("─" * 62)
        print(f"Exit code: {rc}")
        if obfuscate:
            print("  (obfuscated run — polymorphic build-ID injected)")
    pause()


# ─────────────────────────────────────────────────────────────────────────────
# Menu: Language Reference
# ─────────────────────────────────────────────────────────────────────────────

def menu_language_ref():
    clear()
    print_header("JOCKY Language Reference", "Syntax · Types · Stdlib Functions")

    ref = textwrap.dedent("""
    ┌─ Types ──────────────────────────────────────────────────────────────────
    │  num     64-bit integer         var x : num  := 42
    │  dec     64-bit float           var f : dec  := 3.14
    │  text    string (backtick)      var s : text := `hello`
    │  flag    boolean                var b : flag := yes  |  no
    │  raw     opaque pointer         var p : raw  := procs_list()
    │  nothing void (return only)
    │
    ├─ Declarations ──────────────────────────────────────────────────────────
    │  var name : type := expr        Declare + initialise (required)
    │  name <- expr                   Reassign existing variable
    │
    ├─ Control Flow ──────────────────────────────────────────────────────────
    │  check (cond) { ... }           if
    │  check (cond) { ... }
    │    otherwise { ... }            if-else
    │  loop (cond) { ... }            while loop
    │  stop                           break out of loop
    │  skip                           continue to next iteration
    │  give value                     return a value
    │  give                           void return
    │
    ├─ Functions ─────────────────────────────────────────────────────────────
    │  func name(param : type) -> return_type {
    │      body
    │  }
    │  Entry point: func start() -> nothing { ... }
    │
    ├─ Operators ─────────────────────────────────────────────────────────────
    │  +  -  *  /  mod               Arithmetic
    │  is  isnt  gt  lt  gte  lte    Comparison  → flag
    │  also  or  flip                Logical AND / OR / NOT
    │  := (initialise)   <- (assign)
    │
    ├─ Comments ──────────────────────────────────────────────────────────────
    │  ## single-line only
    │
    └─ Standard Library ──────────────────────────────────────────────────────
       report(msg : text)              Print with [JOCKY] prefix
       procs_list()      → raw         Get running process list
       proc_count(p)     → num         Count processes
       proc_name(p, i)   → text        Process name at index
       proc_pid(p, i)    → num         Process PID at index
       proc_kill(pid)                  Terminate process
       net_conns()       → raw         Active TCP/UDP connections
       net_sniff(ms)     → raw         Passive packet capture (ms duration)
       reg_read(k, v)    → text        Read Windows registry value
       reg_list(k)       → raw         List registry subkeys
       file_list(path)   → raw         List directory entries
       file_read(path)   → raw         Read file bytes
       sys_info()        → raw         System info handle
       hash_file(path)   → raw         SHA-256 hash of file
    """)

    if RICH:
        console.print(Panel(ref, border_style="cyan",
                            title="[cyan]JOCKY Language Reference[/cyan]"))
    else:
        print(ref)
    pause()


# ─────────────────────────────────────────────────────────────────────────────
# Menu: About
# ─────────────────────────────────────────────────────────────────────────────

def menu_about():
    clear()
    print_header("About JOCKY", "Compiled Security-Focused Language")

    about = textwrap.dedent("""
    JOCKY is a compiled, statically-typed language designed for
    Windows forensics and cybersecurity tooling.

    Key Properties
    ──────────────
    • Custom syntax — AV parsers cannot execute .jk source files
    • XOR-encrypted strings — static analysis can't read literals
    • Polymorphic builds — different SHA-256 hash on every compile
    • Native .exe via LLVM + MinGW gcc (no Python at runtime)
    • JIT execution for rapid testing via LLVM MCJIT engine

    Technology Stack
    ────────────────
    • Python 3.10+  (compiler toolchain only)
    • llvmlite      — Python bindings to LLVM IR builder + JIT
    • MinGW gcc     — Windows native binary linker

    Compilation Pipeline
    ────────────────────
    .jk source
      1. Lexer      → token stream
      2. Parser     → Abstract Syntax Tree
      3. Semantic   → type-checked AST
      4. Codegen    → LLVM IR module
      5. Obfuscate  → XOR strings + random build-ID + entropy
           ↓
      JIT:    run via MCJIT with Python stdlib callbacks
      Native: gcc links .o + forensics.o → standalone .exe

    Built for Smart India Hackathon (SIH)
    """)

    if RICH:
        console.print(Panel(about, border_style="cyan",
                            title="[cyan]About JOCKY[/cyan]"))
    else:
        print(about)
    pause()


# ─────────────────────────────────────────────────────────────────────────────
# Main menu
# ─────────────────────────────────────────────────────────────────────────────

def main_menu():
    while True:
        clear()

        if RICH:
            banner = Text.from_markup(
                "[bold cyan]   ██╗ ██████╗  ██████╗██╗  ██╗██╗   ██╗[/bold cyan]\n"
                "[bold cyan]   ██║██╔═══██╗██╔════╝██║ ██╔╝╚██╗ ██╔╝[/bold cyan]\n"
                "[bold cyan]   ██║██║   ██║██║     █████╔╝  ╚████╔╝ [/bold cyan]\n"
                "[bold cyan]██ ██║██║   ██║██║     ██╔═██╗   ╚██╔╝  [/bold cyan]\n"
                "[bold cyan]╚█████╔╝╚██████╔╝╚██████╗██║  ██╗  ██║  [/bold cyan]\n"
                "[bold cyan] ╚════╝  ╚═════╝  ╚═════╝╚═╝  ╚═╝  ╚═╝  [/bold cyan]\n"
                "\n"
                "[dim]  Compiled Security Language  ·  Cybersecurity Terminal[/dim]\n"
                "[dim]  LLVM Backend  ·  JIT + Native Binary  ·  AV Evasion Demo[/dim]"
            )
            console.print(Panel(Align.center(banner), border_style="cyan", padding=(0, 4)))
        else:
            print("\n" + "=" * 62)
            print("  J O C K Y   Terminal")
            print("  Compiled Security Language")
            print("=" * 62)

        _divider()
        rprint("  [bold yellow]Main Menu[/bold yellow]")
        _item(1, "Pre-built Cybersecurity Scripts")
        _item(2, "Write / Edit Custom Script")
        _item(3, "Inspect Script        (Tokens · AST · IR)")
        _item(4, "Build Native Binary   (.exe)")
        _item(5, "Language Reference")
        _item(6, "About JOCKY")
        _divider()
        _item(0, "Exit")

        choice = ask("Choice")

        if choice == "1":
            menu_prebuilt_scripts()
        elif choice == "2":
            menu_custom_script()
        elif choice == "3":
            menu_inspect()
        elif choice == "4":
            menu_build()
        elif choice == "5":
            menu_language_ref()
        elif choice == "6":
            menu_about()
        elif choice == "0":
            clear()
            rprint("[cyan]Goodbye![/cyan]")
            sys.exit(0)


# ─────────────────────────────────────────────────────────────────────────────
# Entry point
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    if not RICH:
        print("TIP: Install 'rich' for a better UI:  pip install rich")
        print()
    main_menu()
