# Risk Scoring Model

## Finding residual risk

```
risk_score = 100
  × severity_weight
  × asset_criticality
  × exploitability
  × exposure
  × (1 − detection_coverage × 0.5)
  × confidence
```

| Factor | Range | Source |
|--------|-------|--------|
| severity_weight | 0.05–1.0 | Finding severity |
| asset_criticality | 0–1 | CMDB / asset tags |
| exploitability | 0–1 | EPSS, KEV, path depth |
| exposure | 0–1 | Internet-facing, privilege |
| detection_coverage | 0–1 | Purple-team validation |
| confidence | 0–1 | Agent confidence model |

## Severity weights

| Severity | Weight |
|----------|--------|
| critical | 1.00 |
| high | 0.80 |
| medium | 0.50 |
| low | 0.25 |
| info | 0.05 |

## Enterprise roll-up

- **Asset risk** = max residual finding risk on asset  
- **Domain risk** = p95 of asset risks in domain  
- **Enterprise risk index** = weighted average of domain risks by business criticality  

## Prioritization bands

| Score | Band | SLA guidance |
|-------|------|--------------|
| 80–100 | Critical residual | 24–72h |
| 60–79 | High | 7–14 days |
| 40–59 | Medium | 30 days |
| 20–39 | Low | 90 days |
| 0–19 | Informational | Backlog |
