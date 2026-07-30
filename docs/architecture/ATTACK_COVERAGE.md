# ATT&CK Coverage Model

## Matrix dimensions

- Rows: ATT&CK techniques (enterprise matrix)  
- Columns: Detect | Prevent | Log | Validate  

Each cell is scored 0–1:

| Score | Meaning |
|-------|---------|
| 0.0 | No capability |
| 0.25 | Partial / untested |
| 0.5 | Implemented, not validated |
| 0.75 | Validated in purple exercise |
| 1.0 | Continuous validated coverage |

## Coverage index

```
technique_coverage = mean(detect, prevent, log, validate)
tactic_coverage = mean(technique_coverage for techniques in tactic)
enterprise_coverage = mean(tactic_coverage)
```

## Purple-team feedback loop

1. Coverage agent identifies techniques with validate < 0.5  
2. Adversary emulation planner proposes authorized test  
3. Detection validator + control validation execute under scope  
4. Results update matrix and open remediation findings  

## Detection maturity levels

| Level | Name | Description |
|-------|------|-------------|
| 0 | Initial | Ad-hoc alerts |
| 1 | Managed | Central SIEM, basic rules |
| 2 | Defined | ATT&CK-mapped detections |
| 3 | Measured | Purple-validated coverage metrics |
| 4 | Optimizing | Continuous emulation + auto-remediation guidance |
