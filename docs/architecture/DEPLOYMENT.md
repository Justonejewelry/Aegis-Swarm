# Deployment Guide

## Development

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
docker compose -f deploy/docker/docker-compose.yml up -d postgres redis
uvicorn aegis.api.main:app --reload --port 8080
pytest
```

## Docker full stack

```bash
docker compose -f deploy/docker/docker-compose.yml up --build
```

## Kubernetes (outline)

- Namespace `aegis`
- Deployments: `aegis-api`, `aegis-workers` (per domain optional)
- StatefulSets: Postgres, Redis (or managed services)
- NetworkPolicy: deny by default; allow API→Redis/Postgres; workers→bus
- Secrets via sealed-secrets or external secrets operator
- HPA on API and workers

See `deploy/k8s/` for starter manifests.

## Security hardening checklist

- [ ] Rotate default DB passwords  
- [ ] Enable TLS on API  
- [ ] OIDC SSO for analysts  
- [ ] Per-agent service accounts  
- [ ] Immutable audit log shipping to SIEM  
- [ ] Backup & restore tested for Postgres  

## Redis topology

See [REDIS_TOPOLOGY.md](REDIS_TOPOLOGY.md) and runbook [REDIS_HA.md](../runbooks/REDIS_HA.md).

| Env | Mode | Notes |
|-----|------|--------|
| Dev | `standalone` | Compose `redis` service |
| Prod | `sentinel` or managed HA | Set `AEGIS_REDIS_MODE`, sentinels, password |
| Scale cache | `cluster` | Prefer separate cache URL later if needed |

```bash
export AEGIS_REDIS_MODE=standalone
export AEGIS_REDIS_URL=redis://localhost:6379/0
# Production example:
# export AEGIS_REDIS_MODE=sentinel
# export AEGIS_REDIS_SENTINELS=s1:26379,s2:26379,s3:26379
# export AEGIS_REDIS_MASTER_NAME=aegis-master
```

## Metrics

`GET /metrics` — Prometheus text format when `AEGIS_ENABLE_METRICS=true`.

## Kill-switch

`POST /engagements/{id}/abort?reason=...` — sets status `aborted`, invalidates cache, audits.
