# AEGIS Agent Contract

Every agent implements `BaseAgent` and obeys this contract.

## Required fields

| Field | Description |
|-------|-------------|
| `agent_id` | Stable kebab-case identifier |
| `domain` | command \| blue \| intel \| dfir \| purple \| red \| reporting |
| `version` | Semver string |
| `handle(message)` | Async entrypoint |
| `heartbeat()` | Health report |
| `compute_confidence(...)` | Shared scoring helper |
| `audit(event, details)` | Mandatory decision logging |

## Message protocol

See `schemas/agent_message.schema.json`.

- **task** — work request  
- **result** — structured response  
- **finding** — security finding object(s)  
- **alert** — high-priority notification  
- **heartbeat** — liveness  
- **consensus** — multi-agent agreement  
- **audit** — compliance event  
- **control** — engagement lifecycle  

## Confidence model

```
confidence = clamp(
  0.4 * source_quality
+ 0.3 * min(1, corroboration / 3)
+ 0.2 * max(0, 1 - freshness_hours / 168)
+ 0.1 * (1 - false_positive_rate)
)
```

## Failure conditions (common)

- Missing or inactive `engagement_id`  
- Target outside scope  
- Required telemetry unavailable  
- Downstream timeout  
- Confidence below domain threshold (typically 0.4 for auto-findings)

## Success metrics (common)

- Task completion rate  
- Mean latency  
- Precision / estimated FP rate  
- Audit completeness (100% required)  
- Scope-violation count (must be 0)
