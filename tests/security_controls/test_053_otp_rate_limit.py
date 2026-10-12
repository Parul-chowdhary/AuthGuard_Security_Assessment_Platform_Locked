from app.security_controls.control_053_otp_rate_limit import evaluate

def test_otp_rate_limit_passes_when_control_is_satisfied():
    result = evaluate({'otp_rate_limit_per_minute': 1})
    assert result["status"] == "pass"

def test_otp_rate_limit_fails_when_control_is_not_satisfied():
    result = evaluate({'otp_rate_limit_per_minute': 0})
    assert result["status"] == "fail"
    assert result["id"] == "AG-053"
