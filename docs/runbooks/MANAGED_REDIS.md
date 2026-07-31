# Runbook — Managed Redis (ElastiCache / Memorystore / Azure)

## When to use
Production single-region HA without operating Sentinel yourself.

## Provider notes

### AWS ElastiCache
- Multi-AZ replication group, TLS + AUTH
- `AEGIS_REDIS_URL=rediss://:TOKEN@primary.cache.amazonaws.com:6379/0`
- `AEGIS_REDIS_MODE=standalone`

### GCP Memorystore
- Standard tier HA + PSC
- `AEGIS_REDIS_URL=redis://MEMORYSTORE_IP:6379/0`

### Azure Managed Redis
- Zone redundant, TLS
- `AEGIS_REDIS_URL=rediss://:KEY@NAME.redis.cache.windows.net:6380/0`

## Validation
1. `/health` cache.backend == redis
2. Enqueue + worker process
3. Provider failover — engagements still hydrate from Postgres
