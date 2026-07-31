# AEGIS Swarm

**Autonomous Enterprise Guard & Intelligence System** — multi-agent cyber defense platform for **authorized** SOC operations, purple-team validation, threat assessment, and DFIR.

[![Version](https://img.shields.io/badge/version-0.3.2-blue)](docs/releases/v0.3.0.md)
[![Agents](https://img.shields.io/badge/agents-63-green)](docs/agents/CATALOG.md)
[![License](https://img.shields.io/badge/license-Proprietary-red)]()

> Scope gates, approval lifecycle, and audit logging are mandatory. Red-team agents perform **authorized validation only** — no unauthorized exploitation.

## Status — v0.3.2 (production candidate)

| Layer | Capabilities |
|-------|----------------|
| **Agents** | 63 across Command, Blue, Purple, Red (authorized), Intel, DFIR, Reporting |
| **Control plane** | FastAPI: engagements, dispatch, ingest, audit, metrics, kill-switch |
| **Auth** | Optional API key and/or **OIDC JWT** (JWKS, RS/ES, key rotation) |
| **Messaging** | Redis Streams + DLQ + domain partitions |
| **Storage** | Postgres + Redis cache |
| **Ingestion** | Syslog, Elastic (live), Sentinel (live), CrowdStrike/Defender stubs |
| **Analytics** | Risk scoring, NetworkX GraphStore, ATT&CK mapping |
| **Purple** | Detection validation harness |
| **Compliance** | NIST CSF + CIS matrix |
| **Ops** | K8s Deployments, HPA, NetworkPolicy; managed Redis runbook |
| **Tests** | 48 unit + integration tests |

## Quick start (dev)

```bash
git clone https://github.com/Justonejewelry/Aegis-Swarm.git
cd Aegis-Swarm
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
uvicorn aegis.api.main:app --reload --port 8080
```

API docs: http://localhost:8080/docs

### Worker

```bash
python -m aegis.messaging.worker
```

### Auth (optional)

```bash
export AEGIS_API_KEY=dev-service-key
export AEGIS_OIDC_ISSUER=https://login.microsoftonline.com/<tenant>/v2.0
export AEGIS_OIDC_AUDIENCE=api://aegis-swarm
```

## Key endpoints

| Method | Path | Notes |
|--------|------|--------|
| `POST` | `/engagements` | Create |
| `POST` | `/engagements/{id}/approve` | Activate |
| `POST` | `/engagements/{id}/abort` | Kill-switch |
| `POST` | `/tasks` | Enqueue agent work |
| `POST` | `/ingest` | Connectors → bus |
| `GET` | `/audit` | Audit log |
| `POST` | `/purple/validate` | Detection harness |
| `GET` | `/compliance/matrix` | NIST CSF / CIS |
| `GET` | `/metrics` | Prometheus |
| `GET` | `/health` | Liveness |

## Documentation

- [Architecture](docs/architecture/OVERVIEW.md) · [Roadmap](docs/architecture/ROADMAP.md) · [OIDC](docs/architecture/OIDC.md)
- [Agent catalog](docs/agents/CATALOG.md) · [Managed Redis](docs/runbooks/MANAGED_REDIS.md)
- Releases: [v0.3.0](docs/releases/v0.3.0.md)

## Non-goals

- Unauthorized exploitation or unscoped offensive tooling
- Multi-region Active-Active Redis before single-region HA is proven

## License

Proprietary — authorized defensive use only.
