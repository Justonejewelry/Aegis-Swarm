"""DFIR helpers — evidence chain integrity."""
from aegis.dfir.evidence_chain import EvidenceChain, EvidenceRecord, get_evidence_chain, hash_bytes, hash_json, hash_text

__all__ = ["EvidenceChain", "EvidenceRecord", "get_evidence_chain", "hash_bytes", "hash_json", "hash_text"]
