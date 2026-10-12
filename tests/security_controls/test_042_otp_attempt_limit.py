from app.security_controls.control_042_otp_attempt_limit import evaluate

def test_otp_attempt_limit_passes_when_control_is_satisfied():
    result = evaluate({'otp_attempt_limit': 1})
    assert result["status"] == "pass"

def test_otp_attempt_limit_fails_when_control_is_not_satisfied():
    result = evaluate({'otp_attempt_limit': 0})
    assert result["status"] == "fail"
    assert result["id"] == "AG-042"
