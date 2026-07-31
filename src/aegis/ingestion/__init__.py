"""Telemetry ingestion connectors and pipeline."""
from aegis.ingestion.connectors import (
    Connector,
    CrowdStrikeConnector,
    DefenderConnector,
    ElasticConnector,
    SentinelConnector,
    SyslogConnector,
)
from aegis.ingestion.pipeline import IngestionPipeline

__all__ = [
    "Connector",
    "CrowdStrikeConnector",
    "DefenderConnector",
    "ElasticConnector",
    "IngestionPipeline",
    "SentinelConnector",
    "SyslogConnector",
]
