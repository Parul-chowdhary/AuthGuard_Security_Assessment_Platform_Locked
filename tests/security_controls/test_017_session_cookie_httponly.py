from app.security_controls.control_017_session_cookie_httponly import evaluate

def test_session_cookie_httponly_passes_when_control_is_satisfied():
    result = evaluate({'session_httponly': True})
    assert result["status"] == "pass"

def test_session_cookie_httponly_fails_when_control_is_not_satisfied():
    result = evaluate({'session_httponly': False})
    assert result["status"] == "fail"
    assert result["id"] == "AG-017"
