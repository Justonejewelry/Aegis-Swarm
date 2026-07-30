"""Telemetry connectors — Syslog, Elastic, Sentinel, CrowdStrike, Defender.

All connectors are production-shaped stubs: they accept injected data for tests
and, when credentials are present in Settings, log that a live query would run.
Real HTTP clients can be swapped in without changing the pipeline interface.
"""
from __future__ import annotations

import logging
from typing import Any, Protocol

from aegis.core.settings import get_settings
from aegis.ingestion.normalize import normalize_event

logger = logging.getLogger(__name__)


class Connector(Protocol):
    name: str

    async def fetch(self, since: str | None = None, limit: int = 100) -> list[dict[str, Any]]:
        ...


class SyslogConnector:
    """Accepts pre-buffered syslog-like dicts (production would bind UDP/TCP)."""

    name = "syslog"

    def __init__(self, buffer: list[dict[str, Any]] | None = None) -> None:
        self.buffer = buffer or []

    async def fetch(self, since: str | None = None, limit: int = 100) -> list[dict[str, Any]]:
        batch = self.buffer[:limit]
        self.buffer = self.buffer[limit:]
        return [
            normalize_event(source=self.name, raw=item, severity=item.get("severity", "info"))
            for item in batch
        ]

    def ingest_line(self, line: str, host: str | None = None) -> None:
        self.buffer.append({"message": line, "host": host})


class ElasticConnector:
    """Elasticsearch / OpenSearch style connector."""

    name = "elastic"

    def __init__(
        self,
        hits: list[dict[str, Any]] | None = None,
        index: str | None = None,
        url: str | None = None,
        api_key: str | None = None,
    ) -> None:
        settings = get_settings()
        self.hits = hits or []
        self.index = index or settings.elastic_index
        self.url = url or settings.elastic_url
        self.api_key = api_key or settings.elastic_api_key
        self.configured = bool(self.url and self.api_key)

    async def fetch(self, since: str | None = None, limit: int = 100) -> list[dict[str, Any]]:
        if self.configured and not self.hits:
            logger.info(
                "elastic live query would run against %s index=%s since=%s (stub — inject hits)",
                self.url,
                self.index,
                since,
            )
        batch = self.hits[:limit]
        self.hits = self.hits[limit:]
        out = []
        for hit in batch:
            src = hit.get("_source", hit)
            host = src.get("host")
            if isinstance(host, dict):
                host = host.get("name")
            severity = "info"
            log = src.get("log")
            if isinstance(log, dict):
                severity = str(log.get("level", "info")).lower()
            out.append(
                normalize_event(
                    source=f"elastic:{self.index}",
                    raw=src,
                    host=host,
                    severity=severity,
                )
            )
        return out


class SentinelConnector:
    """Microsoft Sentinel / Log Analytics connector."""

    name = "sentinel"

    def __init__(
        self,
        rows: list[dict[str, Any]] | None = None,
        workspace: str | None = None,
    ) -> None:
        settings = get_settings()
        self.rows = rows or []
        self.workspace = workspace or settings.sentinel_workspace_id or "default"
        self.configured = bool(
            settings.sentinel_workspace_id
            and settings.sentinel_client_id
            and settings.sentinel_client_secret
            and settings.sentinel_tenant_id
        )

    async def fetch(self, since: str | None = None, limit: int = 100) -> list[dict[str, Any]]:
        if self.configured and not self.rows:
            logger.info(
                "sentinel live KQL query would run on workspace %s since=%s (stub — inject rows)",
                self.workspace,
                since,
            )
        batch = self.rows[:limit]
        self.rows = self.rows[limit:]
        return [
            normalize_event(
                source=f"sentinel:{self.workspace}",
                raw=row,
                host=row.get("Computer") or row.get("Host"),
                user=row.get("Account") or row.get("User"),
                severity=str(row.get("Severity") or "info").lower(),
                mitre=row.get("Techniques") or [],
            )
            for row in batch
        ]


class CrowdStrikeConnector:
    """CrowdStrike Falcon detections / incidents connector."""

    name = "crowdstrike"

    def __init__(self, detections: list[dict[str, Any]] | None = None) -> None:
        settings = get_settings()
        self.detections = detections or []
        self.base_url = settings.crowdstrike_base_url
        self.configured = bool(settings.crowdstrike_client_id and settings.crowdstrike_client_secret)

    async def fetch(self, since: str | None = None, limit: int = 100) -> list[dict[str, Any]]:
        if self.configured and not self.detections:
            logger.info(
                "crowdstrike live query would run against %s since=%s (stub — inject detections)",
                self.base_url,
                since,
            )
        batch = self.detections[:limit]
        self.detections = self.detections[limit:]
        out = []
        for d in batch:
            severity = str(d.get("max_severity_displayname") or d.get("severity") or "info").lower()
            out.append(
                normalize_event(
                    source="crowdstrike:falcon",
                    raw=d,
                    host=d.get("device", {}).get("hostname") if isinstance(d.get("device"), dict) else d.get("hostname"),
                    user=d.get("user_name") or d.get("user"),
                    severity=severity,
                    mitre=d.get("mitre_attack") or [],
                )
            )
        return out


class DefenderConnector:
    """Microsoft Defender for Endpoint / XDR connector."""

    name = "defender"

    def __init__(self, alerts: list[dict[str, Any]] | None = None) -> None:
        settings = get_settings()
        self.alerts = alerts or []
        self.configured = bool(
            settings.defender_tenant_id
            and settings.defender_client_id
            and settings.defender_client_secret
        )

    async def fetch(self, since: str | None = None, limit: int = 100) -> list[dict[str, Any]]:
        if self.configured and not self.alerts:
            logger.info("defender live query would run since=%s (stub — inject alerts)", since)
        batch = self.alerts[:limit]
        self.alerts = self.alerts[limit:]
        out = []
        for a in batch:
            severity = str(a.get("severity") or "info").lower()
            out.append(
                normalize_event(
                    source="defender:xdr",
                    raw=a,
                    host=a.get("deviceName") or a.get("computerDnsName"),
                    user=a.get("userPrincipalName") or a.get("accountName"),
                    severity=severity,
                    mitre=a.get("mitreTechniques") or [],
                )
            )
        return out


class IngestionPipeline:
    """Fan-in connectors → normalized event list."""

    def __init__(self, connectors: list[Any] | None = None) -> None:
        self.connectors = connectors or []

    async def collect(self, limit_per_connector: int = 100) -> list[dict[str, Any]]:
        events: list[dict[str, Any]] = []
        for conn in self.connectors:
            try:
                batch = await conn.fetch(limit=limit_per_connector)
                events.extend(batch)
            except Exception:
                logger.exception("connector %s failed", getattr(conn, "name", conn))
        return events


def build_default_pipeline(
    *,
    syslog_buffer: list | None = None,
    elastic_hits: list | None = None,
    sentinel_rows: list | None = None,
    crowdstrike_detections: list | None = None,
    defender_alerts: list | None = None,
) -> IngestionPipeline:
    """Convenience factory used by tests and the API."""
    return IngestionPipeline(
        [
            SyslogConnector(buffer=syslog_buffer),
            ElasticConnector(hits=elastic_hits),
            SentinelConnector(rows=sentinel_rows),
            CrowdStrikeConnector(detections=crowdstrike_detections),
            DefenderConnector(alerts=defender_alerts),
        ]
    )
