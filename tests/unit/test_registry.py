from aegis.core.registry import build_default_agents


def test_registry_has_expected_minimum():
    agents = build_default_agents()
    ids = {a.agent_id for a in agents}
    assert "mission-controller" in ids
    assert "siem-correlator" in ids
    assert "attack-path-modeler" in ids
    assert "threat-hunter" in ids
    assert "ioc-correlator" in ids
    assert len(agents) >= 15
