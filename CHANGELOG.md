# Changelog

## [0.3.1] — 2026-07-30

### Added
- **Real JWKS OIDC verification** (`aegis.auth.oidc`): RS/ES JWT validate, JWKS cache + rotation refresh
- Combined `require_auth` dependency (API key **or** Bearer)
- Docs: `docs/architecture/OIDC.md`
- Tests: valid/expired/wrong-aud/unknown-kid + API key path

## [0.3.0] — 2026-07-30

### Added (roadmap 11–20)
- K8s worker Deployment, HPA, NetworkPolicy; managed Redis runbook; GraphStore load; purple harness; report scheduler; NIST/CIS compliance; chaos tests; production candidate

## [0.2.3] — 2026-07-30

### Added (roadmap 6–10)
- API key gate, GET /audit, live Elastic/Sentinel, POST /ingest, domain streams

## [0.2.2] — 2026-07-30

### Added
- Redis factory, kill-switch, metrics, ROADMAP

## [0.2.0] — 2026-07-30

### Added
- 63 agents, Streams bus, ingestion stubs

## [0.1.0] — 2026-07-30

### Added
- Core multi-agent control plane
