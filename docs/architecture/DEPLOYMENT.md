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
