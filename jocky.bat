@echo off
:: jocky.bat — Windows launcher for the JOCKY CLI / TUI
:: Double-click to open TUI, or call with args for CLI:
::   jocky run scripts/proc_scanner.jk
::   jocky build scripts/kernel_recon.jk
::   jocky byovd scan

setlocal

:: Check Python is available
python --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Python not found on PATH.
    echo         Install Python 3.10+ from https://python.org
    pause
    exit /b 1
)

:: Run JOCKY. When launched with no args (double-click) this opens the TUI.
python "%~dp0jocky.py" %*

:: Keep window open on error when launched by double-click (no args passed)
if "%~1"=="" (
    if errorlevel 1 (
        echo.
        echo [ERROR] JOCKY exited with an error. Check output above.
        pause
    )
)
