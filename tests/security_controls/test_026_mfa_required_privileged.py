from app.security_controls.control_026_mfa_required_privileged import evaluate

def test_mfa_required_privileged_passes_when_control_is_satisfied():
    result = evaluate({'mfa_required_privileged': True})
    assert result["status"] == "pass"

def test_mfa_required_privileged_fails_when_control_is_not_satisfied():
    result = evaluate({'mfa_required_privileged': False})
    assert result["status"] == "fail"
    assert result["id"] == "AG-026"
