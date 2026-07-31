# AEGIS Swarm

**Autonomous Enterprise Guard & Intelligence System** — multi-agent cyber defense control plane for **authorized** SOC, detection engineering, DFIR, and purple-team validation.

![version](https://img.shields.io/badge/version-0.4.2-blue)
![status](https://img.shields.io/badge/release-v0.4.2%20beta-green)

> **Authorized defensive use only.** Do not use against systems without explicit written permission.

**First public beta: [v0.4.2](docs/releases/v0.4.2.md)** · [SECURITY](SECURITY.md) · [LICENSE](LICENSE)

## Quick start

```bash
pip install -e ".[dev]"
./scripts/run_local.sh
# API: http://127.0.0.1:8080/docs

python3 console/launcher.py
# 3D console: http://127.0.0.1:8765/
```

Lab stack (optional):

```bash
docker compose -f deploy/docker/docker-compose.lab.yml up -d
```

Lab credentials (`aegis_dev_only`) are **not for production**.

## 3D Operator Console

```bash
cd console && ./build_console.sh
./dist/AEGIS-Console
```

See [console/README.md](console/README.md).

## Production

```bash
export AEGIS_ENV=production
export AEGIS_API_KEY='…'   # or configure OIDC
export AEGIS_AUDIT_SIGNING_KEY='…'
```

Production **fails closed** if neither API key nor OIDC is set.

## Capabilities

- 63 specialized agents
- Engagement approve/abort gates
- Redis Streams + Sentinel metrics
- Evidence chain, ATT&CK coverage, signed audit, HTML reports
- SQLite offline or Postgres

## License

Proprietary — see [LICENSE](LICENSE).
