from app.security_controls.control_045_otp_constant_time_compare import evaluate

def test_otp_constant_time_compare_passes_when_control_is_satisfied():
    result = evaluate({'otp_constant_time_compare': True})
    assert result["status"] == "pass"

def test_otp_constant_time_compare_fails_when_control_is_not_satisfied():
    result = evaluate({'otp_constant_time_compare': False})
    assert result["status"] == "fail"
    assert result["id"] == "AG-045"
