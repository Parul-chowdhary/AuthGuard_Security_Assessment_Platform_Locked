from app.security_controls.control_018_session_cookie_samesite import evaluate

def test_session_cookie_samesite_passes_when_control_is_satisfied():
    result = evaluate({'session_samesite': 'Lax'})
    assert result["status"] == "pass"

def test_session_cookie_samesite_fails_when_control_is_not_satisfied():
    result = evaluate({'session_samesite': 'not-allowed'})
    assert result["status"] == "fail"
    assert result["id"] == "AG-018"
