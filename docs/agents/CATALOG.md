# AEGIS Agent Catalog

**Total agents:** 64

## Command

| Agent ID | Mission (summary) | Example ATT&CK | Success metric |
|----------|-------------------|----------------|----------------|
| `mission-controller` | Approve/abort engagements; kill-switch | T1001 | engagement control events |
| `global-orchestrator` | Route tasks; enforce scope | T1001 | task queue depth |
| `scheduler` | Cron and event-driven schedules | T1001 | schedule fidelity |
| `task-planner` | Decompose missions into agent tasks | T1001 | plan completeness |
| `resource-manager` | Quota CPU/GPU/API budgets | T1001 | budget adherence |
| `health-monitor` | Agent liveness and SLA | T1001 | MTTR |
| `knowledge-manager` | Curate shared memory and graph | T1001 | knowledge freshness |

## Blue Team

| Agent ID | Mission (summary) | Example ATT&CK | Success metric |
|----------|-------------------|----------------|----------------|
| `soc-coordinator` | Coordinate blue agents and queues | T1078 | MTTD/MTTR |
| `detection-engineer` | Author/tune detection logic | T1059 | rule quality |
| `threat-hunter` | Hypothesis-driven hunts | T1047 | hunt yield |
| `siem-correlator` | Multi-source alert correlation | T1078 | correlation precision |
| `ids-analyst` | NIDS/NIPS alert triage | T1071 | FP reduction |
| `firewall-analyst` | Firewall policy and deny analysis | T1048 | policy gaps found |
| `endpoint-telemetry-analyst` | EDR process/file/network | T1059 | endpoint coverage |
| `authentication-analyst` | Auth anomalies and MFA gaps | T1110 | auth risk score |
| `active-directory-analyst` | AD security posture | T1558 | AD findings |
| `entra-id-analyst` | Entra ID / Conditional Access | T1078 | identity risk |
| `email-security-analyst` | Phish/malware email signals | T1566 | email catch rate |
| `dns-analyst` | DNS tunneling and DGA | T1071.004 | DNS detections |
| `dhcp-analyst` | Rogue DHCP and lease abuse | T1557 | DHCP anomalies |
| `vpn-analyst` | VPN session and geo anomalies | T1133 | VPN risk |
| `network-traffic-analyst` | Flow/PCAP behavioral analytics | T1048 | beaconing found |
| `cloud-security-analyst` | CSPM / cloud identity | T1078.004 | cloud posture |
| `ueba-analyst` | User and entity behavior | T1078 | UEBA alerts |
| `insider-threat-analyst` | Insider risk indicators | T1074 | insider cases |
| `risk-analyst` | Aggregate residual risk | T1486 | risk accuracy |
| `incident-commander` | IR workflow orchestration | T1486 | IR SLA |

## Threat Intelligence

| Agent ID | Mission (summary) | Example ATT&CK | Success metric |
|----------|-------------------|----------------|----------------|
| `ioc-correlator` | Match observables to intel | T1071 | IOC hit rate |
| `campaign-correlator` | Cluster activity into campaigns | T1583 | campaign precision |
| `attack-mapper` | Map to MITRE ATT&CK | T1059 | mapping coverage |
| `cve-intelligence` | Enrich with CVE/EPSS/KEV | T1190 | CVE freshness |
| `threat-intel-fusion` | Merge vendor + open intel | T1583 | fusion quality |
| `ttp-classifier` | Classify behaviors to TTPs | T1059 | classification F1 |

## Digital Forensics

| Agent ID | Mission (summary) | Example ATT&CK | Success metric |
|----------|-------------------|----------------|----------------|
| `timeline-builder` | Merge multi-source timelines | T1070 | timeline completeness |
| `artifact-collector` | Coordinate artifact acquisition | T1005 | chain of custody |
| `memory-analysis-coordinator` | Memory triage coordination | T1055 | volatile evidence |
| `evidence-correlator` | Link artifacts across hosts | T1074 | correlation success |
| `root-cause-analyst` | Hypothesize initial access | T1190 | RCA confidence |
| `incident-reconstruction` | Narrative of attack path | T1078 | reconstruction quality |

## Purple Team

| Agent ID | Mission (summary) | Example ATT&CK | Success metric |
|----------|-------------------|----------------|----------------|
| `detection-validator` | Test whether rules fire | T1059 | validation pass rate |
| `rule-coverage-analyst` | ATT&CK × rule matrix | T1059 | coverage % |
| `logging-coverage-analyst` | Required log source presence | T1070 | log coverage % |
| `control-validation-agent` | Verify control effectiveness | T1562 | control efficacy |
| `attack-coverage-agent` | Technique coverage scoring | T1059 | technique coverage |
| `security-gap-analyst` | Prioritized gap list | T1190 | gap closure rate |

## Red Team Authorized

| Agent ID | Mission (summary) | Example ATT&CK | Success metric |
|----------|-------------------|----------------|----------------|
| `attack-surface-discovery` | Enumerate in-scope surface | T1595 | asset inventory delta |
| `external-exposure-assessment` | External posture review | T1190 | exposure score |
| `identity-exposure-assessment` | Identity attack surface | T1078 | identity exposure |
| `cloud-configuration-assessment` | Cloud CIS/misconfig | T1078.004 | CSPM score |
| `container-security-assessment` | Image/runtime posture | T1610 | container risk |
| `kubernetes-assessment` | K8s RBAC/network policies | T1611 | K8s posture |
| `web-application-assessment` | App security config review | T1190 | app risk |
| `wireless-assessment` | Authorized WLAN posture | T1557 | wireless gaps |
| `active-directory-assessment` | AD tiering and paths | T1558 | AD path risk |
| `privilege-graph-analysis` | Privilege relationship graph | T1078 | graph depth |
| `attack-path-modeler` | Shortest privilege paths | T1021 | paths found |
| `security-control-validation` | Test control bypass resistance | T1562 | control results |
| `adversary-emulation-planner` | Plan ATT&CK emulation | T1059 | plan approval rate |

## Reporting

| Agent ID | Mission (summary) | Example ATT&CK | Success metric |
|----------|-------------------|----------------|----------------|
| `executive-reporting` | Board-level narrative | — | exec readability |
| `technical-reporting` | Analyst-depth reports | — | technical accuracy |
| `dashboard-generator` | SOC/risk dashboards | — | dashboard freshness |
| `compliance-reporting` | Framework mapping outputs | — | framework coverage |
| `recommendation-engine` | Remediation playbooks | — | actionability |
| `risk-prioritization` | Rank residual risk | — | prioritization quality |

## Full agent specification template

For each agent, production docs must include:

1. **Mission** — one-paragraph purpose
2. **Inputs** — message types + telemetry
3. **Outputs** — findings / results schema
4. **Responsibilities** — bullet list
5. **Required telemetry** — log sources
6. **Decision logic** — pseudo-rules
7. **Confidence calculation** — parameters
8. **Communication protocol** — peers
9. **Success metrics** — SLIs
10. **Failure conditions** — refuse/abort
11. **MITRE ATT&CK mappings** — techniques
12. **Reporting format** — fields emitted

Reference implementations live under `src/aegis/agents/`.
