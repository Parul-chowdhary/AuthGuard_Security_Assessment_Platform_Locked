from app.security_controls.control_054_reset_rate_limit import evaluate

def test_reset_rate_limit_passes_when_control_is_satisfied():
    result = evaluate({'password_reset_rate_limit_per_hour': 1})
    assert result["status"] == "pass"

def test_reset_rate_limit_fails_when_control_is_not_satisfied():
    result = evaluate({'password_reset_rate_limit_per_hour': 0})
    assert result["status"] == "fail"
    assert result["id"] == "AG-054"
