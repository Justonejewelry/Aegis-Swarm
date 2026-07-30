from aegis.core.registry import build_default_agents


def test_registry_full_catalog_count():
    agents = build_default_agents()
    ids = {a.agent_id for a in agents}
    assert len(agents) >= 60
    assert len(ids) == len(agents)
    assert "mission-controller" in ids
    assert "siem-correlator" in ids
    assert "attack-path-modeler" in ids
    assert "kubernetes-assessment" in ids
    assert "compliance-reporting" in ids
    assert "dns-analyst" in ids
