@echo off
:: jocky.bat — Windows launcher for the JOCKY CLI / TUI
:: Place this file (or add its folder) on your PATH to use:
::   jocky run scripts/proc_scanner.jk
::   jocky
::
:: It resolves the script relative to wherever jocky.bat lives,
:: so the whole "JOCKY Application" folder stays self-contained.

python "%~dp0jocky.py" %*
