from app.security_controls.016_session_cookie_secure import evaluate

def test_session_cookie_secure_passes_when_control_is_satisfied():
    result = evaluate({'session_secure': True})
    assert result["status"] == "pass"

def test_session_cookie_secure_fails_when_control_is_not_satisfied():
    result = evaluate({'session_secure': False})
    assert result["status"] == "fail"
    assert result["id"] == "AG-016"
