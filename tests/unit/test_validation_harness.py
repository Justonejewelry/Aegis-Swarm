from aegis.purple.validation_harness import DEFAULT_FIXTURES, DetectionValidationHarness

def test_harness_full_coverage():
    rules = set()
    for fx in DEFAULT_FIXTURES:
        rules.update(fx.expected_rule_ids)
    report = DetectionValidationHarness().run(rules)
    assert report.passed == report.total
    assert report.coverage_pct == 100.0

def test_harness_gaps():
    report = DetectionValidationHarness().run({"auth_bruteforce"})
    assert report.failed >= 1
