from app.security_controls.control_078_finding_severity import evaluate

def test_finding_severity_passes_when_control_is_satisfied():
    result = evaluate({'finding_severity': 'info'})
    assert result["status"] == "pass"

def test_finding_severity_fails_when_control_is_not_satisfied():
    result = evaluate({'finding_severity': 'not-allowed'})
    assert result["status"] == "fail"
    assert result["id"] == "AG-078"
