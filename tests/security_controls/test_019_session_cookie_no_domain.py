from app.security_controls.control_019_session_cookie_no_domain import evaluate

def test_session_cookie_no_domain_passes_when_control_is_satisfied():
    result = evaluate({'session_domain': False})
    assert result["status"] == "pass"

def test_session_cookie_no_domain_fails_when_control_is_not_satisfied():
    result = evaluate({'session_domain': True})
    assert result["status"] == "fail"
    assert result["id"] == "AG-019"
