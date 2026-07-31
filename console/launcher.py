#!/usr/bin/env python3
"""AEGIS Swarm 3D Operator Console launcher."""
from __future__ import annotations

import argparse
import os
import sys
import threading
import webbrowser
from pathlib import Path


def resource_root() -> Path:
    if getattr(sys, "frozen", False) and hasattr(sys, "_MEIPASS"):
        return Path(sys._MEIPASS) / "static"
    return Path(__file__).resolve().parent / "static"


def main() -> int:
    parser = argparse.ArgumentParser(description="AEGIS Swarm 3D Console")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--api", default=os.environ.get("AEGIS_API", "http://127.0.0.1:8080"))
    parser.add_argument("--no-browser", action="store_true")
    args = parser.parse_args()

    static = resource_root()
    index = static / "index.html"
    if not index.exists():
        print(f"UI missing at {index}", file=sys.stderr)
        return 1

    from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer

    class Handler(SimpleHTTPRequestHandler):
        def __init__(self, *a, **k):
            super().__init__(*a, directory=str(static), **k)

        def log_message(self, fmt, *args_):
            sys.stdout.write("[console] " + (fmt % args_) + "\n")

        def end_headers(self):
            self.send_header("Cache-Control", "no-cache")
            super().end_headers()

    server = ThreadingHTTPServer((args.host, args.port), Handler)
    url = f"http://{args.host}:{args.port}/"
    print(f"AEGIS 3D Console → {url}")
    print(f"API target: {args.api}")
    print("Help: press ? inside the console · Authorized defensive use only")

    if not args.no_browser:
        threading.Timer(0.6, lambda: webbrowser.open(url)).start()

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down console")
        server.shutdown()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
