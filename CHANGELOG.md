# Changelog

## [0.2.3] — 2026-07-30

### Added (roadmap 6–10)
- **API key gate** (`X-API-Key` when `AEGIS_API_KEY` set) on mutating routes
- **`GET /audit`** — Postgres-backed audit log (global or per engagement)
- **Live Elastic + Sentinel connectors** — OAuth/ApiKey + paginated queries via httpx
- **`POST /ingest`** — connector collect → normalize → task-bus enqueue
- **Domain-partitioned streams** — `aegis:tasks:{blue|intel|...}` via `TaskBus.enqueue(..., domain=)`
- Ingestion pipeline module with severity-based agent routing
- Tests: api_key, ingestion enqueue, stream_for_domain

## [0.2.2] — 2026-07-30

### Added
- Swarm consensus roadmap, Redis client factory, kill-switch, Prometheus metrics

## [0.2.1] — 2026-07-30

### Added
- Redis cache layer, Postgres engagement wiring

## [0.2.0] — 2026-07-30

### Added
- 63 agents, Redis Streams bus + worker, ingestion stubs

## [0.1.0] — 2026-07-30

### Added
- Multi-agent core, FastAPI control plane, Docker/K8s starters, CI
