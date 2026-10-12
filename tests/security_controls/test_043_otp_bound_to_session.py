from app.security_controls.043_otp_bound_to_session import evaluate

def test_otp_bound_to_session_passes_when_control_is_satisfied():
    result = evaluate({'otp_session_bound': True})
    assert result["status"] == "pass"

def test_otp_bound_to_session_fails_when_control_is_not_satisfied():
    result = evaluate({'otp_session_bound': False})
    assert result["status"] == "fail"
    assert result["id"] == "AG-043"
