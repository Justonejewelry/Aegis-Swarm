# Changelog

## [0.2.2] — 2026-07-30

### Added
- Swarm consensus **roadmap** (`docs/architecture/ROADMAP.md`) — next 20 steps
- **Redis client factory** (`aegis.core.redis_client`) — standalone | sentinel | cluster
- Settings: `AEGIS_REDIS_MODE`, `AEGIS_REDIS_SENTINELS`, `AEGIS_REDIS_MASTER_NAME`, `AEGIS_REDIS_PASSWORD`
- TaskBus + Cache connect through factory
- **Kill-switch** `POST /engagements/{id}/abort`
- **Prometheus** `GET /metrics`
- Docs: `REDIS_TOPOLOGY.md`, runbook `REDIS_HA.md`
- Unit tests for redis client failure paths

## [0.2.1] — 2026-07-30

### Added
- **Redis caching layer** (`aegis.storage.cache`)
- Lookup order: process memory → Redis cache → Postgres
- PostgreSQL storage layer + engagement wiring
- Worker: cache-aware engagement load + DLQ
- 24+ unit tests

## [0.2.0] — 2026-07-30

### Added
- Full catalog agent coverage — 63 agents
- Redis Streams task bus + worker
- Ingestion connector stubs

## [0.1.0] — 2026-07-30

### Added
- Multi-agent core, FastAPI control plane, risk scoring, Docker/K8s starters, CI
