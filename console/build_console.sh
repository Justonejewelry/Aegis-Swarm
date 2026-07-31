#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
python3 -m pip install -q pyinstaller
python3 -m PyInstaller --noconfirm --clean aegis_console.spec
echo "Artifact: $(pwd)/dist/AEGIS-Console"
