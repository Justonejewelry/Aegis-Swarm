# AEGIS Swarm — Enterprise Architecture Overview

## Mission

AEGIS (Autonomous Enterprise Guard & Intelligence System) is a **cloud-native multi-agent AI platform** that operates as an autonomous Security Operations capability for:

- Continuous asset discovery and telemetry correlation  
- Threat assessment and ATT&CK mapping  
- Detection engineering and coverage analysis  
- Authorized purple-team control validation  
- DFIR support and incident reconstruction  
- Executive and technical risk reporting  

**Non-negotiables:** defined engagement scope, immutable audit logs, human approval gates for validation modes, remediation-first outputs.

---

## Logical architecture

```mermaid
flowchart TB
  subgraph Ingest["Data Ingestion Plane"]
    SYS[Syslog / Windows / Linux Audit]
    NIDS[Zeek / Suricata / Snort]
    EDR[CrowdStrike / Defender / Wazuh]
    CLOUD[Azure / AWS / GCP / K8s]
    IDP[Entra ID / AD / M365]
    TICKET[Jira / ServiceNow / GitHub]
  end

  subgraph Bus["Event Bus + Shared Memory"]
    MQ[(Redis Streams / NATS)]
    VEC[(Vector DB)]
    KG[(Knowledge Graph)]
    PG[(PostgreSQL)]
  end

  subgraph Command["Command Domain"]
    MC[Mission Controller]
    ORCH[Global Orchestrator]
    SCH[Scheduler]
    HM[Health Monitor]
  end

  subgraph Blue["Blue Team Domain"]
    SOC[SOC Coordinator]
    DET[Detection Engineer]
    HUNT[Threat Hunter]
    SIEM[SIEM Correlator]
  end

  subgraph Intel["Threat Intelligence"]
    IOC[IOC Correlator]
    ATT[ATT&CK Mapper]
    CVE[CVE Intelligence]
  end

  subgraph Purple["Purple Team"]
    DV[Detection Validator]
    CV[Control Validation]
    GAP[Security Gap Analyst]
  end

  subgraph Red["Red Team Authorized Validation"]
    SURF[Attack Surface Discovery]
    PATH[Attack Path Modeler]
    EMU[Adversary Emulation Planner]
  end

  subgraph DFIR["Digital Forensics"]
    TL[Timeline Builder]
    RC[Root Cause Analyst]
  end

  subgraph Report["Reporting"]
    EXEC[Executive Reporting]
    TECH[Technical Reporting]
    COMP[Compliance Reporting]
  end

  Ingest --> MQ
  MQ --> ORCH
  ORCH --> Blue & Intel & Purple & Red & DFIR
  Blue & Intel & Purple & Red & DFIR --> PG & VEC & KG
  PG --> Report
  MC --> ORCH
```

---

## Control flow (engagement lifecycle)

```mermaid
sequenceDiagram
  participant Analyst
  participant API
  participant Mission as Mission Controller
  participant Orch as Orchestrator
  participant Agents as Domain Agents
  participant Audit as Audit Log

  Analyst->>API: Create engagement + scope
  API->>Mission: pending_approval
  Analyst->>API: Approve engagement
  Mission->>Audit: approval event
  Mission->>Orch: status=ACTIVE
  loop Continuous / scheduled tasks
    Orch->>Agents: scoped task
    Agents->>Audit: decision + evidence refs
    Agents->>Orch: findings / results
  end
  Orch->>API: executive + technical reports
  Analyst->>API: Complete / Abort
```

---

## Deployment topology

| Layer | Technology |
|-------|------------|
| API / control plane | FastAPI, Uvicorn |
| Messaging | Redis Streams (dev), NATS/Kafka (prod) |
| System of record | PostgreSQL 16 |
| Hot cache / locks | Redis |
| Embeddings / similarity | Vector DB (pgvector or dedicated) |
| Relationship analysis | Knowledge graph (NetworkX in-process → Neo4j prod) |
| Runtime | Kubernetes + Docker |
| Mesh / mTLS | Optional service mesh (Linkerd/Istio) |
| Identity | OIDC + RBAC (Least privilege per agent domain) |
| Observability | Prometheus metrics, structured audit logs |

---

## Zero Trust principles

1. Every task carries `engagement_id` and is refused if engagement is not `ACTIVE`.  
2. Agents validate targets against engagement scope before work.  
3. Privileged validation actions require explicit `allowed_validation_actions`.  
4. All agent decisions write to `audit_log`.  
5. Human kill-switch via Mission Controller `abort`.  
6. Network policies isolate agent domains; API is the only north-south entry.

---

## Workflow pipeline

```
Asset Discovery → Telemetry Collection → Normalization
  → Threat Intel Correlation → Detection Analytics → Behavior Analytics
  → Threat Assessment → Risk Prioritization → Control Validation
  → Executive & Technical Reporting
```
