# Changelog

## [0.1.0] — 2026-07-30

### Added
- Multi-agent core: `BaseAgent`, confidence model, orchestrator with engagement scope gates
- FastAPI control plane: `/health`, `/agents`, `/engagements`, `/dispatch`
- Agent registry with **20 implemented agents** across 7 domains
- Risk scoring model and prioritization helpers
- JSON schemas for agent messages, engagements, findings
- PostgreSQL schema (`schemas/sql/init.sql`)
- Docker Compose + Kubernetes starter manifests
- Architecture docs, ATT&CK coverage model, threat assessment methodology
- Unit tests for risk, orchestrator, attack path, registry, auth analyst
- GitHub Actions CI (pytest + ruff)

### Security posture
- Tasks require `ACTIVE` engagement
- Authorized red/purple agents only produce plans and validated findings (no exploit execution)
- Audit hooks on agent decisions
