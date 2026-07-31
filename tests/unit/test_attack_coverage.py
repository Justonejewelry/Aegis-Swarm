from aegis.analytics.attack_coverage import TECHNIQUE_CATALOG, build_coverage_matrix, matrix_to_csv, techniques_from_findings

def test_catalog_expanded():
    assert len(TECHNIQUE_CATALOG) >= 50

def test_techniques_from_findings():
    counts = techniques_from_findings([
        {"mitre_techniques": ["T1110", "T1078"]},
        {"mitre": ["T1110"]},
        {"mitre_techniques": ["T1059.001"]},
    ])
    assert counts["T1110"] == 2
    assert counts["T1059"] >= 1

def test_matrix_structure():
    m = build_coverage_matrix(findings=[{"mitre_techniques": ["T1110"]}])
    assert m["total_techniques"] >= 50
    assert "by_tactic" in m
    assert "T1110" in matrix_to_csv(m)
