"""Ingestion connectors and pipeline tests."""
from __future__ import annotations

from uuid import uuid4

import pytest

from aegis.ingestion.connectors import ElasticConnector, SentinelConnector, SyslogConnector
from aegis.ingestion.pipeline import IngestionPipeline
from aegis.messaging.bus import TaskBus, stream_for_domain


@pytest.mark.asyncio
async def test_syslog_and_pipeline():
    syslog = SyslogConnector()
    syslog.ingest_line("sshd: Failed password for root", host="gw1")
    elastic = ElasticConnector(hits=[{"_source": {"message": "login", "host": "web1"}}])
    sentinel = SentinelConnector(rows=[{"Computer": "dc1", "Account": "alice", "Severity": "High"}])
    pipe = IngestionPipeline([syslog, elastic, sentinel])
    events = await pipe.collect()
    assert len(events) == 3
    assert all("event_id" in e and "source" in e for e in events)
    assert events[2]["source"].startswith("sentinel:")


@pytest.mark.asyncio
async def test_pipeline_enqueue_to_bus():
    syslog = SyslogConnector()
    syslog.ingest_line("critical alert", host="fw1")
    syslog.buffer.append({"message": "boom", "severity": "critical", "host": "fw1"})
    pipe = IngestionPipeline([syslog])
    bus = TaskBus()
    await bus.connect()
    eid = uuid4()
    result = await pipe.collect_and_enqueue(engagement_id=eid, bus=bus, domain="blue")
    assert result["enqueued"] >= 1
    assert result["task_ids"]
    tasks = await bus.dequeue("test-worker", count=10)
    assert any(t.get("domain") == "blue" for t in tasks)


def test_stream_for_domain():
    assert stream_for_domain(None) == "aegis:tasks"
    assert stream_for_domain("blue") == "aegis:tasks:blue"
    assert stream_for_domain("intel") == "aegis:tasks:intel"
    assert stream_for_domain("unknown-xyz") == "aegis:tasks"


@pytest.mark.asyncio
async def test_elastic_normalizes_injected_hits():
    c = ElasticConnector(hits=[{"_source": {"message": "x", "host": {"name": "h1"}, "log": {"level": "Warning"}}}])
    events = await c.fetch(limit=10)
    assert len(events) == 1
    assert events[0]["host"] == "h1"
