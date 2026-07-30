"""Redis / in-memory cache unit tests."""
from __future__ import annotations

from uuid import uuid4

import pytest

from aegis.core.models import (
    Engagement,
    EngagementMode,
    EngagementStatus,
    Finding,
    Scope,
    Severity,
)
from aegis.storage.cache import Cache, reset_cache_for_tests


@pytest.fixture
def cache() -> Cache:
    reset_cache_for_tests()
    c = Cache(url="redis://localhost:6379/15", enabled=True)
    c._client = None
    c._connected = False
    return c


@pytest.mark.asyncio
async def test_engagement_roundtrip(cache: Cache):
    eng = Engagement(
        engagement_id=uuid4(),
        name="cache-test",
        mode=EngagementMode.HUNT,
        scope=Scope(in_scope_domains=["corp.local"]),
        status=EngagementStatus.ACTIVE,
        approver="lead",
    )
    await cache.set_engagement(eng)
    loaded = await cache.get_engagement(eng.engagement_id)
    assert loaded is not None
    assert loaded.name == "cache-test"
    assert loaded.mode == EngagementMode.HUNT
    assert loaded.status == EngagementStatus.ACTIVE
    assert "corp.local" in loaded.scope.in_scope_domains
    assert cache.hits >= 1


@pytest.mark.asyncio
async def test_engagement_miss(cache: Cache):
    assert await cache.get_engagement(uuid4()) is None
    assert cache.misses >= 1


@pytest.mark.asyncio
async def test_findings_roundtrip(cache: Cache):
    eid = uuid4()
    findings = [
        Finding(
            engagement_id=eid,
            title="f1",
            severity=Severity.HIGH,
            category="auth",
            confidence=0.8,
            risk_score=60,
            sources=["test"],
        ),
        Finding(
            engagement_id=eid,
            title="f2",
            severity=Severity.LOW,
            category="net",
            confidence=0.5,
            risk_score=20,
            sources=["test"],
        ),
    ]
    await cache.set_findings(eid, findings)
    loaded = await cache.get_findings(eid)
    assert loaded is not None
    assert len(loaded) == 2
    assert loaded[0].title == "f1"
    assert loaded[1].severity == Severity.LOW


@pytest.mark.asyncio
async def test_invalidate(cache: Cache):
    eng = Engagement(
        name="gone",
        mode=EngagementMode.ASSESS,
        scope=Scope(),
        status=EngagementStatus.DRAFT,
    )
    await cache.set_engagement(eng)
    await cache.set_findings(eng.engagement_id, [])
    await cache.invalidate_engagement(eng.engagement_id)
    assert await cache.get_engagement(eng.engagement_id) is None
    assert await cache.get_findings(eng.engagement_id) is None


@pytest.mark.asyncio
async def test_disabled_cache():
    c = Cache(enabled=False)
    eng = Engagement(
        name="x",
        mode=EngagementMode.ASSESS,
        scope=Scope(),
        status=EngagementStatus.DRAFT,
    )
    await c.set_engagement(eng)
    assert await c.get_engagement(eng.engagement_id) is None
    assert c.backend == "disabled"


@pytest.mark.asyncio
async def test_stats(cache: Cache):
    s = cache.stats()
    assert s["backend"] == "memory"
    assert "hits" in s and "misses" in s
