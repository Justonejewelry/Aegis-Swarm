#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
export PYTHONPATH="$ROOT/src"
export AEGIS_DB_MODE="${AEGIS_DB_MODE:-sqlite}"
export AEGIS_SQLITE_PATH="${AEGIS_SQLITE_PATH:-/tmp/aegis.db}"
export AEGIS_ENV="${AEGIS_ENV:-development}"
export AEGIS_PERSIST_FINDINGS=true
export AEGIS_PERSIST_AUDIT=true
HOST="${HOST:-127.0.0.1}"
PORT="${PORT:-8080}"
echo "AEGIS Swarm starting (sqlite=$AEGIS_SQLITE_PATH) on $HOST:$PORT"
exec python -m uvicorn aegis.api.main:app --host "$HOST" --port "$PORT"
