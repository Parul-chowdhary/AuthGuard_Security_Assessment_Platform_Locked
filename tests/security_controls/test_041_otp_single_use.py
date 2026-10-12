from app.security_controls.control_041_otp_single_use import evaluate

def test_otp_single_use_passes_when_control_is_satisfied():
    result = evaluate({'otp_single_use': True})
    assert result["status"] == "pass"

def test_otp_single_use_fails_when_control_is_not_satisfied():
    result = evaluate({'otp_single_use': False})
    assert result["status"] == "fail"
    assert result["id"] == "AG-041"
