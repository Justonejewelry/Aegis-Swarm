from uuid import uuid4
from aegis.dfir.evidence_chain import EvidenceChain, hash_text

def test_register_and_verify():
    chain = EvidenceChain()
    eid = uuid4()
    r1 = chain.register(eid, label="memory.raw", content=b"\\x00\\x01volatile")
    r2 = chain.register(eid, label="timeline.json", content={"events": [1, 2, 3]})
    assert r2.prev_hash == r1.chain_hash
    assert chain.verify(eid)["intact"] is True

def test_tamper_detected():
    chain = EvidenceChain()
    eid = uuid4()
    chain.register(eid, label="a", content="one")
    r2 = chain.register(eid, label="b", content="two")
    r2.content_hash = hash_text("mutated")
    assert chain.verify(eid)["intact"] is False

def test_hash_helpers_stable():
    assert hash_text("abc") == hash_text("abc")
