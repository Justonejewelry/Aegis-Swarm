# AEGIS Swarm

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
cd aegis-swarm
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
docker compose -f deploy/docker/docker-compose.yml up -d
uvicorn aegis.api.main:app --reload --port 8080
```

API docs: http://localhost:8080/docs

## Documentation

- [Architecture](docs/architecture/OVERVIEW.md)
- [Agent catalog](docs/agents/CATALOG.md)
- [Agent contract](docs/agents/CONTRACT.md)
- [Threat assessment methodology](docs/architecture/THREAT_ASSESSMENT.md)
- [ATT&CK coverage model](docs/architecture/ATTACK_COVERAGE.md)
- [Risk scoring](docs/architecture/RISK_SCORING.md)
- [Deployment guide](docs/architecture/DEPLOYMENT.md)
- [Runbooks](docs/runbooks/)

## License

Proprietary / enterprise — configure for your organization. Authorized use only.
