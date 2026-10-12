from app.security_controls.control_046_otp_delivery_redaction import evaluate

def test_otp_delivery_redaction_passes_when_control_is_satisfied():
    result = evaluate({'otp_delivery_redacted_in_logs': True})
    assert result["status"] == "pass"

def test_otp_delivery_redaction_fails_when_control_is_not_satisfied():
    result = evaluate({'otp_delivery_redacted_in_logs': False})
    assert result["status"] == "fail"
    assert result["id"] == "AG-046"
