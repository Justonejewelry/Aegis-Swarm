# Changelog

## [0.2.1] — 2026-07-30

### Added
- **PostgreSQL storage layer** (`aegis.storage`): async SQLAlchemy models + repositories for Engagement, Finding, AuditLog, AgentRegistry
- **Engagement wiring**: create / approve / list / get hydrate from Postgres; workers load durable engagements before synthesizing
- API: `GET /engagements` (memory + DB), `_resolve_engagement` memory-first then DB, findings rehydrate from DB
- Repository helpers: `EngagementRepository.upsert` / `to_engagement`, `FindingRepository.create` + `to_finding`, `AuditRepository.log`
- API persistence hooks: engagements, findings, and audit events written when DB is available
- **GraphStore** (`aegis.analytics.graph_store`): shared NetworkX DiGraph per engagement
- HTML executive report endpoint: `GET /engagements/{id}/report`
- Settings module (`aegis.core.settings`) with env-driven connector credentials
- Expanded ingestion: CrowdStrike + Defender connectors
- Worker: automatic finding persistence + DLQ + counters + DB engagement load
- 18 unit tests passing

## [0.2.0] — 2026-07-30

### Added
- **Full catalog agent coverage** — 63 implemented agents (all domains)
- Compact agent helpers (`AnalyticAgent`, `ResultAgent`)
- **Redis Streams task bus** with in-memory fallback (`aegis.messaging.bus`)
- **Worker loop** (`aegis.messaging.worker`) for background dispatch
- API `POST /tasks` enqueue endpoint
- **Ingestion connectors** (stubs): Syslog, Elastic, Microsoft Sentinel + normalize pipeline
- Tests for registry count, bus, worker, ingestion

## [0.1.0] — 2026-07-30

### Added
- Multi-agent core: `BaseAgent`, confidence model, orchestrator with engagement scope gates
- FastAPI control plane: `/health`, `/agents`, `/engagements`, `/dispatch`
- Agent registry with initial agents across 7 domains
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
