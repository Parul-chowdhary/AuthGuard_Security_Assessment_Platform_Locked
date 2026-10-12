from app.security_controls.control_038_password_not_logged import evaluate

def test_password_not_logged_passes_when_control_is_satisfied():
    result = evaluate({'password_logging_disabled': True})
    assert result["status"] == "pass"

def test_password_not_logged_fails_when_control_is_not_satisfied():
    result = evaluate({'password_logging_disabled': False})
    assert result["status"] == "fail"
    assert result["id"] == "AG-038"
