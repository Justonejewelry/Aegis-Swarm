# AEGIS Swarm

[![Release](https://img.shields.io/github/v/release/Justonejewelry/Aegis-Swarm?include_prereleases&style=flat-square)](https://github.com/Justonejewelry/Aegis-Swarm/releases)
[![CI](https://img.shields.io/github/actions/workflow/status/Justonejewelry/Aegis-Swarm/ci.yml?branch=main&style=flat-square&label=CI)](https://github.com/Justonejewelry/Aegis-Swarm/actions)
[![License](https://img.shields.io/badge/license-Proprietary-lightgrey?style=flat-square)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.11%2B-blue?style=flat-square)](https://www.python.org/)
[![Agents](https://img.shields.io/badge/agents-63%20implemented%20%2F%2064%20catalog-purple?style=flat-square)](docs/agents/CATALOG.md)

**Autonomous Enterprise Guard & Intelligence System**

Enterprise-grade multi-agent AI platform for authorized cyber defense, threat assessment, purple-team validation, detection engineering, DFIR support, and executive risk reporting.

> **Scope boundary:** AEGIS operates only within approved engagement scopes, produces immutable audit logs, and prioritizes defensive outcomes and remediation. Offensive validation agents perform *authorized control validation and adversary emulation planning* — not unauthorized exploitation.

## Capabilities

| Domain | Role |
|--------|------|
| **Command** | Mission control, orchestration, scheduling, health |
| **Blue Team** | SOC analytics, detection, hunting, IR coordination |
| **Threat Intel** | IOC/TTP fusion, ATT&CK mapping, CVE intelligence |
| **DFIR** | Timeline, artifacts, reconstruction, root cause |
| **Purple Team** | Detection & control validation, coverage gaps |
| **Red Team (Authorized)** | Attack-surface & path modeling, control validation |
| **Reporting** | Executive, technical, compliance, risk prioritization |

## Quick start (dev)

```bash
git clone https://github.com/Justonejewelry/Aegis-Swarm.git
cd Aegis-Swarm
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
docker compose -f deploy/docker/docker-compose.yml up -d
uvicorn aegis.api.main:app --reload --port 8080
```

API docs: http://localhost:8080/docs

## Current status (v0.2.1)

- **63 agents** registered · Redis Streams + DLQ + worker
- **PostgreSQL storage** for engagements, findings, audit
- **GraphStore** (NetworkX) shared by attack-path & privilege-graph agents
- HTML executive report + Streamlit dashboard + Grafana stubs
- 5 ingestion connectors (Syslog, Elastic, Sentinel, CrowdStrike, Defender)
- 17 unit tests passing

## Task bus & workers

```bash
# Terminal A — API
uvicorn aegis.api.main:app --port 8080

# Terminal B — worker (Redis if available, else in-memory)
python -m aegis.messaging.worker
```

Enqueue: `POST /tasks` with `engagement_id`, `recipient`, `payload`.

## Documentation

- [Architecture](docs/architecture/OVERVIEW.md)
- [Agent catalog](docs/agents/CATALOG.md)
- [Agent contract](docs/agents/CONTRACT.md)
- [Threat assessment methodology](docs/architecture/THREAT_ASSESSMENT.md)
- [ATT&CK coverage model](docs/architecture/ATTACK_COVERAGE.md)
- [Risk scoring](docs/architecture/RISK_SCORING.md)
- [Deployment guide](docs/architecture/DEPLOYMENT.md)
- [v0.2.1 / v0.2.0 release notes](docs/releases/v0.2.0.md)
- [v0.1.0 release notes](docs/releases/v0.1.0.md)
- [Runbooks](docs/runbooks/)

## Topics

`cybersecurity` · `soc` · `purple-team` · `threat-hunting` · `mitre-attack` · `multi-agent` · `fastapi` · `dfir`

## License

Proprietary / enterprise — configure for your organization. Authorized use only.
