from app.security_controls.052_login_rate_limit import evaluate

def test_login_rate_limit_passes_when_control_is_satisfied():
    result = evaluate({'login_rate_limit_per_minute': 1})
    assert result["status"] == "pass"

def test_login_rate_limit_fails_when_control_is_not_satisfied():
    result = evaluate({'login_rate_limit_per_minute': 0})
    assert result["status"] == "fail"
    assert result["id"] == "AG-052"
