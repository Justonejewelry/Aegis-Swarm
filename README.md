# AEGIS Swarm

**Autonomous Enterprise Guard & Intelligence System** — multi-agent cyber defense control plane for **authorized** SOC, detection engineering, DFIR, and purple-team validation.

![version](https://img.shields.io/badge/version-0.4.2-blue)

> **Authorized defensive use only.** Do not use against systems without explicit written permission.

## Quick start (fully operational offline)

```bash
pip install -e ".[dev]"
./scripts/run_local.sh
# API: http://127.0.0.1:8080/health
```

Uses **SQLite** + in-memory Redis fallback (no Docker required).

### Lab stack

```bash
docker compose -f deploy/docker/docker-compose.lab.yml up -d
```

Lab credentials (`aegis_dev_only`) are **for local lab only — never production**.

### Background workers

```bash
export PYTHONPATH=src
export AEGIS_WORKER_DOMAINS="*"
python -m aegis.messaging.worker
```

## Production checklist

- `AEGIS_ENV=production` → **fails closed** unless `AEGIS_API_KEY` and/or OIDC is set
- Optional: `AEGIS_TRUSTED_HOSTS`, `AEGIS_CORS_ORIGINS`, `AEGIS_RATE_LIMIT_PER_MINUTE`
- `AEGIS_AUDIT_SIGNING_KEY` for signed `/audit/export`
- Bind behind TLS gateway; restrict `/metrics` and `/redis/status`

See [SECURITY.md](SECURITY.md).

## License

Proprietary — see [LICENSE](LICENSE).
