from aegis.audit.signed_export import build_signed_export, verify_signature

def test_signed_export_roundtrip():
    export = build_signed_export([{"audit_id": 1, "event": "x"}], secret="test-secret-key")
    assert export["signing"] == "hmac-sha256"
    payload = {k: v for k, v in export.items() if k not in ("signature", "signing")}
    assert verify_signature(payload, export["signature"], "test-secret-key")

def test_unsigned_when_no_secret():
    export = build_signed_export([{"event": "x"}], secret=None)
    assert export["signing"] == "unsigned"
