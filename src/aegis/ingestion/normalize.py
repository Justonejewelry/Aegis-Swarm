"""Normalize heterogeneous telemetry into AEGIS events."""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any
from uuid import uuid4


def utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def normalize_event(
    *,
    source: str,
    raw: dict[str, Any],
    host: str | None = None,
    user: str | None = None,
    severity: str = "info",
    mitre: list[str] | None = None,
) -> dict[str, Any]:
    return {
        "event_id": str(uuid4()),
        "source": source,
        "ts": raw.get("ts") or raw.get("@timestamp") or utcnow_iso(),
        "host": host or raw.get("host") or raw.get("hostname"),
        "user": user or raw.get("user") or raw.get("username"),
        "severity": severity or raw.get("severity", "info"),
        "mitre": mitre or raw.get("mitre") or [],
        "message": raw.get("message") or raw.get("msg") or "",
        "raw": raw,
    }
