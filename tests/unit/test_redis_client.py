"""Redis client factory unit tests (no live Redis required for failure paths)."""
from __future__ import annotations

import pytest

from aegis.core.redis_client import create_redis_client


@pytest.mark.asyncio
async def test_standalone_unreachable_returns_none():
    client = await create_redis_client(
        mode="standalone",
        url="redis://127.0.0.1:59999/0",
    )
    assert client is None


@pytest.mark.asyncio
async def test_sentinel_without_hosts_returns_none():
    client = await create_redis_client(mode="sentinel", sentinels=None)
    assert client is None


@pytest.mark.asyncio
async def test_cluster_unreachable_returns_none():
    client = await create_redis_client(
        mode="cluster",
        url="redis://127.0.0.1:59998/0",
    )
    assert client is None
