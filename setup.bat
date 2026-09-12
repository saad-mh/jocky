@echo off
:: setup.bat — One-time setup for JOCKY Application on Windows
:: Run this once before using the application.
:: It installs Python dependencies and builds the C stdlib.

echo.
echo ============================================================
echo   JOCKY Application Setup
echo ============================================================
echo.

:: 1. Check Python
python --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Python not found. Install Python 3.10+ from https://python.org
    pause
    exit /b 1
)

for /f "tokens=2 delims= " %%v in ('python --version 2^>^&1') do set PYVER=%%v
echo [OK] Python %PYVER% found.

:: 2. Install Python dependencies
echo.
echo [*] Installing Python dependencies...
python -m pip install -r "%~dp0requirements.txt" --quiet
if errorlevel 1 (
    echo [ERROR] pip install failed. Check your internet connection.
    pause
    exit /b 1
)
echo [OK] Python dependencies installed.

:: 3. Test llvmlite
echo.
echo [*] Testing llvmlite...
python -c "import llvmlite; print('[OK] llvmlite', llvmlite.__version__)"
if errorlevel 1 (
    echo [ERROR] llvmlite import failed.
    pause
    exit /b 1
)

:: 4. Test rich
python -c "import rich; print('[OK] rich', rich.__version__)" 2>nul
if errorlevel 1 (
    echo [WARN] rich not installed - TUI will fall back to plain text.
)

:: 5. Build forensics.o (optional - requires MinGW gcc)
echo.
echo [*] Checking for gcc (MinGW)...
where gcc >nul 2>&1
if errorlevel 1 (
    echo [WARN] gcc not found on PATH.
    echo        Native binary (.exe) output will not work.
    echo        JIT execution (--run) works without gcc.
    echo        To install MinGW: https://www.mingw-w64.org/
) else (
    echo [OK] gcc found.
    echo [*] Building stdlib/forensics.o...
    python "%~dp0compiler\build_stdlib.py"
    if errorlevel 1 (
        echo [WARN] forensics.o build failed. JIT mode still works.
    ) else (
        echo [OK] forensics.o built successfully.
    )
)

:: 6. Done
echo.
echo ============================================================
echo   Setup complete!
echo.
echo   Run the interactive terminal:
echo     python jocky_terminal.py
echo.
echo   Or use the CLI:
echo     jocky run scripts/proc_scanner.jk
echo     jocky run scripts/threat_hunter.jk
echo ============================================================
echo.
pause
