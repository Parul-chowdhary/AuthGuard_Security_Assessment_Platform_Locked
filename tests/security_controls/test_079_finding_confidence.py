from app.security_controls.079_finding_confidence import evaluate

def test_finding_confidence_passes_when_control_is_satisfied():
    result = evaluate({'finding_confidence': 'low'})
    assert result["status"] == "pass"

def test_finding_confidence_fails_when_control_is_not_satisfied():
    result = evaluate({'finding_confidence': 'not-allowed'})
    assert result["status"] == "fail"
    assert result["id"] == "AG-079"
