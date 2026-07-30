# Runbook — Redis HA for AEGIS

## Symptoms
- Workers idle; `/health` shows cache backend `memory` unexpectedly
- API logs: `Redis unavailable` / `in-memory bus`

## Checks
1. `redis-cli -h $HOST ping` (or Sentinel: `SENTINEL get-master-addr-by-name aegis-master`)
2. Confirm `AEGIS_REDIS_MODE` matches topology
3. NetworkPolicy / security groups allow API + workers → Redis/Sentinel ports
4. Auth: `AEGIS_REDIS_PASSWORD` if required

## Failover (Sentinel)
1. Sentinels promote a replica automatically
2. Clients via factory rediscover primary on next command / reconnect
3. Verify: enqueue `POST /tasks` and confirm worker processes

## Recovery after total Redis loss
1. Restore Redis from backup if durable AOF/RDB required for streams backlog
2. Restart workers after Redis healthy
3. Engagements/findings: rehydrate from Postgres (cache warms on access)
4. Re-queue failed tasks from DLQ stream `aegis:dlq` if present

## Kill-switch interaction
`POST /engagements/{id}/abort` sets status `aborted` in Postgres + invalidates cache.
Workers refuse non-CONTROL work for non-ACTIVE engagements (orchestrator gate).
