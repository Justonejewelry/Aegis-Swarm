# AEGIS Swarm — 3D Operator Console

Single-pane 3D GUI for engagements, agents, dispatch, evidence, ATT&CK, audit, Redis/Sentinel, and metrics.

## Run from source

```bash
./scripts/run_local.sh   # API
python3 console/launcher.py
```

## Build single-file executable

```bash
cd console && ./build_console.sh
./dist/AEGIS-Console
```

## Config

- `AEGIS_API` — control plane URL (default `http://127.0.0.1:8080`)
- `localStorage.aegis_api_key` — optional API key

Authorized defensive use only. See SECURITY.md.
