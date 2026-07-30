import pytest

from aegis.ingestion.connectors import (
    CrowdStrikeConnector,
    DefenderConnector,
    ElasticConnector,
    IngestionPipeline,
    SentinelConnector,
    SyslogConnector,
    build_default_pipeline,
)


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
async def test_crowdstrike_and_defender():
    cs = CrowdStrikeConnector(
        detections=[{"device": {"hostname": "laptop1"}, "max_severity_displayname": "High", "user_name": "bob"}]
    )
    defn = DefenderConnector(alerts=[{"deviceName": "ws02", "severity": "medium", "userPrincipalName": "carol@corp"}])
    events = await IngestionPipeline([cs, defn]).collect()
    assert len(events) == 2
    assert events[0]["source"] == "crowdstrike:falcon"
    assert events[1]["source"] == "defender:xdr"
    assert events[0]["host"] == "laptop1"


@pytest.mark.asyncio
async def test_build_default_pipeline():
    pipe = build_default_pipeline(
        syslog_buffer=[{"message": "test"}],
        elastic_hits=[{"_source": {"message": "e"}}],
    )
    events = await pipe.collect()
    assert len(events) >= 2
