from app.security_controls.027_mfa_recovery_rate_limited import evaluate

def test_mfa_recovery_rate_limited_passes_when_control_is_satisfied():
    result = evaluate({'mfa_recovery_rate_limited': True})
    assert result["status"] == "pass"

def test_mfa_recovery_rate_limited_fails_when_control_is_not_satisfied():
    result = evaluate({'mfa_recovery_rate_limited': False})
    assert result["status"] == "fail"
    assert result["id"] == "AG-027"
