from app.security_controls.024_login_generic_errors import evaluate

def test_login_generic_errors_passes_when_control_is_satisfied():
    result = evaluate({'login_generic_errors': True})
    assert result["status"] == "pass"

def test_login_generic_errors_fails_when_control_is_not_satisfied():
    result = evaluate({'login_generic_errors': False})
    assert result["status"] == "fail"
    assert result["id"] == "AG-024"
