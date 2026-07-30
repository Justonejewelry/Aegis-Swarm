# Threat Assessment Methodology

## Stages

1. **Scope lock** — engagement approved with explicit in/out of scope  
2. **Asset & identity inventory** — CMDB + discovery agents  
3. **Telemetry readiness** — logging coverage analyst  
4. **Intel enrichment** — IOC / CVE / campaign fusion  
5. **Detection analytics** — SIEM correlation, NIDS, EDR  
6. **Behavior analytics** — UEBA, beaconing, lateral movement models  
7. **Path analysis** — privilege graph + attack path modeler  
8. **Control validation** — purple team (authorized)  
9. **Risk prioritization** — residual risk scoring  
10. **Reporting** — executive + technical + compliance  

## Finding quality bar

A finding is auto-promoted only if:

- confidence ≥ 0.55 (configurable)  
- ≥1 evidence reference  
- severity assigned  
- ≥1 remediation action  
- engagement still ACTIVE  

## Investigation workflow

```
Alert/Finding → Triage → Scope check → Enrich → Hunt/DFIR
  → Containment recommendation → Eradication guidance
  → Recovery verification → Lessons learned → Coverage update
```
