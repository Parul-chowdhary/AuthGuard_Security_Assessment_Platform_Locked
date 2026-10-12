from app.security_controls.control_080_finding_remediation import evaluate

def test_finding_remediation_passes_when_control_is_satisfied():
    result = evaluate({'finding_remediation': 'present'})
    assert result["status"] == "pass"

def test_finding_remediation_fails_when_control_is_not_satisfied():
    result = evaluate({'finding_remediation': ''})
    assert result["status"] == "fail"
    assert result["id"] == "AG-080"
