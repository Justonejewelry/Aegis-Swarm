"""DFIR evidence chain integrity — SHA-256 hashing and linked chain records."""
from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any
from uuid import UUID, uuid4


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def hash_bytes(data: bytes, algo: str = "sha256") -> str:
    h = hashlib.new(algo)
    h.update(data)
    return h.hexdigest()


def hash_text(text: str, algo: str = "sha256") -> str:
    return hash_bytes(text.encode("utf-8"), algo=algo)


def hash_json(obj: Any, algo: str = "sha256") -> str:
    payload = json.dumps(obj, sort_keys=True, default=str, separators=(",", ":"))
    return hash_text(payload, algo=algo)


@dataclass
class EvidenceRecord:
    evidence_id: str
    engagement_id: str
    label: str
    content_hash: str
    algo: str = "sha256"
    source: str | None = None
    media_type: str | None = None
    size_bytes: int | None = None
    collected_by: str | None = None
    prev_hash: str | None = None
    chain_hash: str | None = None
    created_at: str = field(default_factory=lambda: utcnow().isoformat())
    meta: dict[str, Any] = field(default_factory=dict)

    def compute_chain_hash(self) -> str:
        body = {
            "evidence_id": self.evidence_id,
            "engagement_id": self.engagement_id,
            "label": self.label,
            "content_hash": self.content_hash,
            "algo": self.algo,
            "source": self.source,
            "media_type": self.media_type,
            "size_bytes": self.size_bytes,
            "collected_by": self.collected_by,
            "prev_hash": self.prev_hash,
            "created_at": self.created_at,
            "meta": self.meta,
        }
        return hash_json(body)


class EvidenceChain:
    def __init__(self) -> None:
        self._by_eng: dict[str, list[EvidenceRecord]] = {}

    def register(
        self,
        engagement_id: UUID | str,
        *,
        label: str,
        content: bytes | str | dict[str, Any] | None = None,
        content_hash: str | None = None,
        source: str | None = None,
        media_type: str | None = None,
        collected_by: str | None = None,
        meta: dict[str, Any] | None = None,
    ) -> EvidenceRecord:
        eid = str(engagement_id)
        if content_hash is None:
            if content is None:
                raise ValueError("content or content_hash required")
            if isinstance(content, bytes):
                content_hash = hash_bytes(content)
                size = len(content)
            elif isinstance(content, str):
                content_hash = hash_text(content)
                size = len(content.encode("utf-8"))
            else:
                content_hash = hash_json(content)
                size = len(json.dumps(content, default=str).encode("utf-8"))
        else:
            size = meta.get("size_bytes") if meta else None
        chain = self._by_eng.setdefault(eid, [])
        prev = chain[-1].chain_hash if chain else None
        rec = EvidenceRecord(
            evidence_id=str(uuid4()),
            engagement_id=eid,
            label=label,
            content_hash=content_hash,
            source=source,
            media_type=media_type,
            size_bytes=size if isinstance(size, int) else None,
            collected_by=collected_by,
            prev_hash=prev,
            meta=meta or {},
        )
        rec.chain_hash = rec.compute_chain_hash()
        chain.append(rec)
        return rec

    def list_for(self, engagement_id: UUID | str) -> list[EvidenceRecord]:
        return list(self._by_eng.get(str(engagement_id), []))

    def verify(self, engagement_id: UUID | str) -> dict[str, Any]:
        chain = self.list_for(engagement_id)
        breaks: list[dict[str, Any]] = []
        prev: str | None = None
        for i, rec in enumerate(chain):
            if rec.prev_hash != prev:
                breaks.append({"index": i, "evidence_id": rec.evidence_id, "reason": "prev_hash_mismatch"})
            expected = rec.compute_chain_hash()
            if rec.chain_hash != expected:
                breaks.append({"index": i, "evidence_id": rec.evidence_id, "reason": "chain_hash_mismatch"})
            prev = rec.chain_hash
        return {
            "engagement_id": str(engagement_id),
            "count": len(chain),
            "intact": len(breaks) == 0,
            "breaks": breaks,
            "tip_hash": chain[-1].chain_hash if chain else None,
        }

    def export(self, engagement_id: UUID | str) -> list[dict[str, Any]]:
        return [asdict(r) for r in self.list_for(engagement_id)]


_chain: EvidenceChain | None = None


def get_evidence_chain() -> EvidenceChain:
    global _chain
    if _chain is None:
        _chain = EvidenceChain()
    return _chain
