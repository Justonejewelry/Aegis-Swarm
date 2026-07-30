# AEGIS Swarm — Consensus Roadmap (next 20 steps)

**Convened:** 2026-07-30  
**Facilitator:** mission-controller (synthesized domain votes)  
**Constraint:** authorized SOC / purple-team only; remediation-first; scope gates immutable

## Swarm input (summary)

| Domain | Priority ask |
|--------|----------------|
| **Command** | Kill-switch, HA Redis, metrics, approval audit trail |
| **Blue** | Live ingestion adapters, SIEM correlation depth, alert routing |
| **Intel** | IOC enrichment feeds, ATT&CK coverage gaps auto-map |
| **Purple** | Detection validation harness, coverage matrix export |
| **Red (authorized)** | Attack-path persistence, control-validation playbooks only |
| **DFIR** | Timeline export, evidence chain integrity |
| **Reporting** | Scheduled exec reports, Grafana panels, compliance packs |

**Consensus ranking:** control-plane reliability → data plane → analytic depth → presentation.

## Next 20 steps (ordered)

1. **Redis client factory** (standalone | sentinel | cluster) — *done in this cycle*
2. **Engagement kill-switch API** (`POST .../abort`) — *done in this cycle*
3. **Prometheus `/metrics`** — *done in this cycle*
4. **Document Redis topology** (Sentinel-first HA) — *done in this cycle*
5. **Wire TaskBus + Cache through factory** — *done in this cycle*
6. Optional API key gate (`AEGIS_API_KEY`) on mutating routes
7. Postgres-backed audit query API (`GET /audit`)
8. Live Elastic/Sentinel connector adapters (auth + pagination)
9. Ingestion → task bus auto-enqueue pipeline
10. Domain-partitioned stream keys (optional scale path)
11. Worker HPA / multi-replica k8s manifests
12. Managed Redis runbook (ElastiCache / Memorystore / Azure)
13. Attack-path GraphStore → Postgres edge persistence
14. Detection validation fixture harness (purple)
15. Executive report PDF/HTML scheduler
16. OIDC SSO for analyst UI
17. NetworkPolicy + mTLS between API and workers
18. Chaos test: Redis failover + worker resume
19. Compliance mapping pack (NIST CSF / CIS) in reporting agents
20. Tag **v0.3.0** production-candidate release

## Acceptance themes for v0.3.0

- Failover: Redis primary loss does not lose approved engagement state (Postgres is source of truth; cache rebuilds).
- Kill-switch aborts in-flight worker acceptance of new tasks for that engagement.
- Metrics scrapeable by Grafana/Prometheus.
- At least one live ingestion path from Elastic or Sentinel in a lab.

## Non-goals (explicit)

- Unauthorized exploitation or live offensive tooling outside approved validation modes.
- Multi-region Active-Active Redis before single-region HA is proven.
