"""API engagement lifecycle smoke tests (no external Redis/Postgres required)."""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from aegis.api.main import app
from aegis.core.settings import get_settings


@pytest.fixture(autouse=True)
def _clear_settings():
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


@pytest.fixture
def client():
    return TestClient(app)


def test_health(client: TestClient):
    r = client.get("/health")
    assert r.status_code == 200
    body = r.json()
    assert body.get("status") == "ok"
    assert body.get("agents", 0) >= 20


def test_list_agents(client: TestClient):
    r = client.get("/agents")
    assert r.status_code == 200
    agents = r.json()
    assert isinstance(agents, list)
    assert len(agents) >= 20


def test_engagement_lifecycle(client: TestClient):
    r = client.post(
        "/engagements",
        json={
            "name": "integration-smoke",
            "mode": "assess",
            "scope": {
                "in_scope_cidrs": ["10.0.0.0/8"],
                "in_scope_domains": ["lab.example.local"],
                "allowed_validation_actions": ["read_only_probe"],
            },
        },
    )
    assert r.status_code == 200, r.text
    eng = r.json()
    eid = eng["engagement_id"]
    assert eng["name"] == "integration-smoke"

    r = client.get("/engagements")
    assert r.status_code == 200
    assert any(str(e.get("engagement_id")) == str(eid) for e in r.json())

    r = client.post(f"/engagements/{eid}/approve", params={"approver": "soc-lead"})
    assert r.status_code == 200, r.text

    r = client.post(f"/engagements/{eid}/abort", params={"reason": "integration_test"})
    assert r.status_code == 200, r.text


def test_compliance_matrix(client: TestClient):
    r = client.get("/compliance/matrix")
    assert r.status_code == 200
    matrix = r.json()
    assert isinstance(matrix, list)
    assert any(m.get("framework") == "NIST-CSF" for m in matrix)


def test_purple_validate(client: TestClient):
    r = client.post(
        "/purple/validate",
        json={"active_rule_ids": ["auth_bruteforce", "siem_failed_logon_spike"]},
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert "coverage_pct" in body
    assert body["total"] >= 1


def test_metrics_endpoint(client: TestClient):
    r = client.get("/metrics")
    assert r.status_code == 200
