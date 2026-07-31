"""Redis / Sentinel monitoring metrics for Prometheus and ops endpoints."""
from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class RedisTopologyStatus:
    mode: str = "unknown"
    connected: int = 0
    backend: str = "none"
    master_name: str = ""
    configured_sentinels: int = 0
    reachable_sentinels: int = 0
    master_host: str = ""
    master_port: int = 0
    replica_count: int = 0
    sentinel_masters_ok: int = 0
    last_check_ts: float = 0.0
    error: str = ""
    details: dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return {
            "mode": self.mode,
            "connected": bool(self.connected),
            "backend": self.backend,
            "master_name": self.master_name or None,
            "configured_sentinels": self.configured_sentinels,
            "reachable_sentinels": self.reachable_sentinels,
            "master_host": self.master_host or None,
            "master_port": self.master_port or None,
            "replica_count": self.replica_count,
            "sentinel_masters_ok": self.sentinel_masters_ok,
            "last_check_ts": self.last_check_ts,
            "error": self.error or None,
            "details": self.details,
        }


_last: RedisTopologyStatus = RedisTopologyStatus()


def get_last_redis_status() -> RedisTopologyStatus:
    return _last


async def probe_redis_topology() -> RedisTopologyStatus:
    global _last
    status = RedisTopologyStatus(last_check_ts=time.time())
    try:
        from aegis.core.settings import get_settings
        settings = get_settings()
        status.mode = settings.redis_mode
        status.master_name = settings.redis_master_name or "aegis-master"
        if settings.redis_mode == "sentinel":
            await _probe_sentinel(status, settings)
        elif settings.redis_mode == "cluster":
            await _probe_cluster(status, settings)
        else:
            await _probe_standalone(status, settings)
    except Exception as e:
        status.error = str(e)
        status.connected = 0
        status.backend = "memory"
    _last = status
    return status


async def _probe_standalone(status: RedisTopologyStatus, settings: Any) -> None:
    from aegis.core.redis_client import create_redis_client
    client = await create_redis_client(mode="standalone", url=settings.redis_url, password=settings.redis_password)
    if client is None:
        status.backend = "memory"
        status.error = "standalone unreachable"
        return
    try:
        await client.ping()
        status.connected = 1
        status.backend = "redis"
        info = await client.info("replication")
        status.replica_count = int(info.get("connected_slaves") or info.get("connected_replicas") or 0)
        status.details["role"] = info.get("role")
    finally:
        try:
            await client.aclose()
        except Exception:
            pass


async def _probe_cluster(status: RedisTopologyStatus, settings: Any) -> None:
    from aegis.core.redis_client import create_redis_client
    client = await create_redis_client(mode="cluster", url=settings.redis_url, password=settings.redis_password)
    if client is None:
        status.backend = "memory"
        status.error = "cluster unreachable"
        return
    try:
        await client.ping()
        status.connected = 1
        status.backend = "redis"
    finally:
        try:
            await client.aclose()
        except Exception:
            pass


async def _probe_sentinel(status: RedisTopologyStatus, settings: Any) -> None:
    try:
        import redis.asyncio as redis
        from redis.asyncio.sentinel import Sentinel
    except ImportError:
        status.error = "redis package missing"
        status.backend = "memory"
        return
    nodes: list[tuple[str, int]] = []
    for part in (settings.redis_sentinels or "").split(","):
        part = part.strip()
        if not part:
            continue
        host, _, port = part.partition(":")
        nodes.append((host, int(port or 26379)))
    status.configured_sentinels = len(nodes)
    if not nodes:
        status.error = "AEGIS_REDIS_SENTINELS empty"
        status.backend = "memory"
        return
    password = settings.redis_password
    master_name = settings.redis_master_name or "aegis-master"
    status.master_name = master_name
    reachable = 0
    masters_ok = 0
    for host, port in nodes:
        try:
            r = redis.Redis(host=host, port=port, password=password, socket_timeout=1.5)
            if await r.ping():
                reachable += 1
                try:
                    info = await r.execute_command("SENTINEL", "MASTER", master_name)
                    meta = _flat_to_dict(info)
                    flags = str(meta.get("flags", ""))
                    if "o_down" not in flags and "s_down" not in flags and "disconnected" not in flags:
                        masters_ok += 1
                    if not status.master_host:
                        status.master_host = str(meta.get("ip") or "")
                        try:
                            status.master_port = int(meta.get("port") or 0)
                        except (TypeError, ValueError):
                            pass
                    try:
                        status.replica_count = int(meta.get("num-slaves") or 0)
                    except (TypeError, ValueError):
                        pass
                    status.details.setdefault("masters", {})[f"{host}:{port}"] = {
                        "flags": flags, "ip": meta.get("ip"), "port": meta.get("port"),
                    }
                except Exception as e:
                    status.details.setdefault("sentinel_errors", {})[f"{host}:{port}"] = str(e)
            await r.aclose()
        except Exception as e:
            status.details.setdefault("sentinel_errors", {})[f"{host}:{port}"] = str(e)
    status.reachable_sentinels = reachable
    status.sentinel_masters_ok = masters_ok
    try:
        sentinel = Sentinel(nodes, socket_timeout=2.0, password=password)
        client = sentinel.master_for(master_name, decode_responses=True, password=password)
        await client.ping()
        status.connected = 1
        status.backend = "redis"
        try:
            await client.aclose()
        except Exception:
            pass
    except Exception as e:
        status.connected = 0
        status.backend = "memory"
        status.error = status.error or f"master_for failed: {e}"


def _flat_to_dict(seq: Any) -> dict[str, Any]:
    if isinstance(seq, dict):
        return seq
    out: dict[str, Any] = {}
    it = list(seq or [])
    for i in range(0, len(it) - 1, 2):
        k, v = it[i], it[i + 1]
        if isinstance(k, bytes):
            k = k.decode()
        if isinstance(v, bytes):
            v = v.decode()
        out[str(k)] = v
    return out


def status_to_prometheus(status: RedisTopologyStatus) -> str:
    lines = [
        "# HELP aegis_redis_connected 1 if Redis primary client is reachable",
        "# TYPE aegis_redis_connected gauge",
        f'aegis_redis_connected{{mode="{status.mode}"}} {status.connected}',
        "# HELP aegis_redis_sentinel_configured Number of configured Sentinel endpoints",
        "# TYPE aegis_redis_sentinel_configured gauge",
        f"aegis_redis_sentinel_configured {status.configured_sentinels}",
        "# HELP aegis_redis_sentinel_reachable Number of Sentinel endpoints that respond to PING",
        "# TYPE aegis_redis_sentinel_reachable gauge",
        f"aegis_redis_sentinel_reachable {status.reachable_sentinels}",
        "# HELP aegis_redis_sentinel_masters_ok Sentinels reporting master not s_down/o_down",
        "# TYPE aegis_redis_sentinel_masters_ok gauge",
        f"aegis_redis_sentinel_masters_ok {status.sentinel_masters_ok}",
        "# HELP aegis_redis_replica_count Replicas reported for monitored master",
        "# TYPE aegis_redis_replica_count gauge",
        f"aegis_redis_replica_count {status.replica_count}",
        "# HELP aegis_redis_last_check_timestamp Unix time of last topology probe",
        "# TYPE aegis_redis_last_check_timestamp gauge",
        f"aegis_redis_last_check_timestamp {status.last_check_ts:.0f}",
        "# HELP aegis_redis_mode_info Active Redis topology mode (1=active)",
        "# TYPE aegis_redis_mode_info gauge",
    ]
    for m in ("standalone", "sentinel", "cluster"):
        lines.append(f'aegis_redis_mode_info{{mode="{m}"}} {1 if status.mode == m else 0}')
    return "\n".join(lines) + "\n"
