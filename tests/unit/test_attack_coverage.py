from aegis.analytics.attack_coverage import build_coverage_matrix, matrix_to_csv, techniques_from_findings

def test_techniques_from_findings():
    counts = techniques_from_findings([
        {"mitre_techniques": ["T1110", "T1078"]},
        {"mitre": ["T1110"]},
    ])
    assert counts["T1110"] == 2

def test_matrix_structure():
    m = build_coverage_matrix(findings=[{"mitre_techniques": ["T1110"]}])
    assert m["total_techniques"] > 0
    assert "T1110" in matrix_to_csv(m)
