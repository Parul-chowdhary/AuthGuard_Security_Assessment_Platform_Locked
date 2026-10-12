from app.security_controls.control_040_otp_expiry import evaluate

def test_otp_expiry_passes_when_control_is_satisfied():
    result = evaluate({'otp_ttl_seconds': 1})
    assert result["status"] == "pass"

def test_otp_expiry_fails_when_control_is_not_satisfied():
    result = evaluate({'otp_ttl_seconds': 0})
    assert result["status"] == "fail"
    assert result["id"] == "AG-040"
