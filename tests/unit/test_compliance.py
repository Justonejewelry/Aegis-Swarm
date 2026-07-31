from aegis.compliance.frameworks import CIS_CONTROLS, NIST_CSF, coverage_matrix, map_findings_to_controls

def test_coverage_matrix_nonempty():
    m = coverage_matrix()
    assert len(m) == len(NIST_CSF) + len(CIS_CONTROLS)

def test_map_findings():
    mapped = map_findings_to_controls([{"title": "Brute force", "mitre_techniques": ["T1110"]}])
    assert any(c["control_id"] == "PR.AC" for c in mapped[0]["controls"])
