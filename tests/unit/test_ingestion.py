import pytest

from aegis.ingestion.connectors import ElasticConnector, IngestionPipeline, SentinelConnector, SyslogConnector


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
