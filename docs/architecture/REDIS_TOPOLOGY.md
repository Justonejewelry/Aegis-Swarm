# AEGIS Redis Topology Guide

## Workloads

| Workload | Keys / streams | Scale driver |
|----------|----------------|--------------|
| Task bus | `aegis:tasks`, `aegis:results`, `aegis:dlq` | Worker throughput |
| Cache | `aegis:eng:{id}`, `aegis:findings:{id}` | Engagement/finding churn |

## Recommended topologies

### Development
- **Standalone** Redis 7 (Compose service `redis`)
- `AEGIS_REDIS_MODE=standalone`
- `AEGIS_REDIS_URL=redis://localhost:6379/0`

### Production (default)
- **Sentinel HA** or **managed primary–replica**
- Why: Streams keys are few; HA matters more than sharding the bus
- `AEGIS_REDIS_MODE=sentinel`
- `AEGIS_REDIS_SENTINELS=s1:26379,s2:26379,s3:26379`
- `AEGIS_REDIS_MASTER_NAME=aegis-master`

### Cluster
- Use when **cache** keyspace or **partitioned streams** need horizontal scale
- `AEGIS_REDIS_MODE=cluster`
- **Caveat:** each stream key hashes to one slot — partition streams by domain if scaling the bus

## Client factory

`aegis.core.redis_client.create_redis_client` selects topology from settings.
TaskBus and Cache both call it; agents never open Redis connections directly.

## Failure behavior

| Layer | On Redis loss |
|-------|----------------|
| Cache | In-memory fallback; rebuild from Postgres |
| Task bus | In-memory queue (single process only) |
| Engagements | Postgres remains source of truth |

Production multi-worker deployments **must** keep Redis available (Sentinel/managed).
