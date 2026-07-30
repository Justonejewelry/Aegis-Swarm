"""Telemetry connector stubs — Syslog, Elastic, Microsoft Sentinel."""
from __future__ import annotations

import logging
from typing import Any, Protocol

from aegis.ingestion.normalize import normalize_event

logger = logging.getLogger(__name__)


class Connector(Protocol):
    name: str

    async def fetch(self, since: str | None = None, limit: int = 100) -> list[dict[str, Any]]:
        ...


class SyslogConnector:
    """Stub: accepts pre-buffered syslog-like dicts."""

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
    """Stub: accepts injected Elasticsearch hits."""

    name = "elastic"

    def __init__(self, hits: list[dict[str, Any]] | None = None, index: str = "logs-*") -> None:
        self.hits = hits or []
        self.index = index

    async def fetch(self, since: str | None = None, limit: int = 100) -> list[dict[str, Any]]:
        batch = self.hits[:limit]
        self.hits = self.hits[limit:]
        out = []
        for hit in batch:
            src = hit.get("_source", hit)
            host = src.get("host", {}).get("name") if isinstance(src.get("host"), dict) else src.get("host")
            severity = src.get("log", {}).get("level", "info") if isinstance(src.get("log"), dict) else "info"
            out.append(normalize_event(source=f"elastic:{self.index}", raw=src, host=host, severity=severity))
        return out


class SentinelConnector:
    """Stub: Microsoft Sentinel / Log Analytics query results."""

    name = "sentinel"

    def __init__(self, rows: list[dict[str, Any]] | None = None, workspace: str = "default") -> None:
        self.rows = rows or []
        self.workspace = workspace

    async def fetch(self, since: str | None = None, limit: int = 100) -> list[dict[str, Any]]:
        batch = self.rows[:limit]
        self.rows = self.rows[limit:]
        return [
            normalize_event(
                source=f"sentinel:{self.workspace}",
                raw=row,
                host=row.get("Computer") or row.get("Host"),
                user=row.get("Account") or row.get("User"),
                severity=(row.get("Severity") or "info").lower(),
                mitre=row.get("Techniques") or [],
            )
            for row in batch
        ]


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
