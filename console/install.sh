#!/usr/bin/env bash
set -euo pipefail
PREFIX="${PREFIX:-$HOME/.local}"
BIN="$PREFIX/bin"
mkdir -p "$BIN"
ROOT="$(cd "$(dirname "$0")" && pwd)"
if [[ -x "$ROOT/dist/AEGIS-Console" ]]; then
  SRC="$ROOT/dist/AEGIS-Console"
elif [[ -x "$ROOT/AEGIS-Console" ]]; then
  SRC="$ROOT/AEGIS-Console"
else
  echo "Build first: ./build_console.sh" >&2
  exit 1
fi
install -m 755 "$SRC" "$BIN/aegis-console"
echo "Installed: $BIN/aegis-console"
