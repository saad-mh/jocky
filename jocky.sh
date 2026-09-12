#!/usr/bin/env bash
# jocky.sh — Unix/macOS launcher for the JOCKY CLI / TUI
# Usage:
#   bash jocky.sh run scripts/proc_scanner.jk
#   bash jocky.sh
#
# To make it a bare command:
#   chmod +x jocky.sh && ln -s "$(pwd)/jocky.sh" /usr/local/bin/jocky

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
python3 "$SCRIPT_DIR/jocky.py" "$@"
