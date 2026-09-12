#!/usr/bin/env bash
# setup.sh — One-time setup for JOCKY Application on Linux/macOS
# Run:  bash setup.sh

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo ""
echo "============================================================"
echo "  JOCKY Application Setup"
echo "============================================================"
echo ""

# 1. Check Python 3.10+
if ! command -v python3 &>/dev/null; then
    echo "[ERROR] python3 not found. Install Python 3.10+ first."
    exit 1
fi
PYVER=$(python3 --version 2>&1)
echo "[OK] $PYVER"

# 2. Install dependencies
echo ""
echo "[*] Installing Python dependencies..."
python3 -m pip install -r "$SCRIPT_DIR/requirements.txt" --quiet
echo "[OK] Dependencies installed."

# 3. Test llvmlite
echo ""
echo "[*] Testing llvmlite..."
python3 -c "import llvmlite; print('[OK] llvmlite', llvmlite.__version__)"

# 4. Test rich
python3 -c "import rich; print('[OK] rich', rich.__version__)" 2>/dev/null \
    || echo "[WARN] rich not installed - plain text fallback will be used."

# 5. Build forensics.o
echo ""
echo "[*] Checking for gcc..."
if command -v gcc &>/dev/null; then
    echo "[OK] gcc found: $(gcc --version | head -1)"
    echo "[*] Building stdlib/forensics.o..."
    python3 "$SCRIPT_DIR/compiler/build_stdlib.py"
    echo "[OK] forensics.o built."
else
    echo "[WARN] gcc not found. Native binary output disabled."
    echo "       JIT execution still works without gcc."
fi

# 6. Make launchers executable
chmod +x "$SCRIPT_DIR/jocky.sh" 2>/dev/null || true

echo ""
echo "============================================================"
echo "  Setup complete!"
echo ""
echo "  Run the interactive terminal:"
echo "    python3 jocky_terminal.py"
echo ""
echo "  Or use the CLI:"
echo "    python3 jocky.py run scripts/proc_scanner.jk"
echo "    bash jocky.sh run scripts/threat_hunter.jk"
echo "============================================================"
echo ""
