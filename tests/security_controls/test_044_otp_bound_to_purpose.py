from app.security_controls.044_otp_bound_to_purpose import evaluate

def test_otp_bound_to_purpose_passes_when_control_is_satisfied():
    result = evaluate({'otp_purpose_bound': True})
    assert result["status"] == "pass"

def test_otp_bound_to_purpose_fails_when_control_is_not_satisfied():
    result = evaluate({'otp_purpose_bound': False})
    assert result["status"] == "fail"
    assert result["id"] == "AG-044"
