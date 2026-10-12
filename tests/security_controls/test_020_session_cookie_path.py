from app.security_controls.020_session_cookie_path import evaluate

def test_session_cookie_path_passes_when_control_is_satisfied():
    result = evaluate({'session_path': '/'})
    assert result["status"] == "pass"

def test_session_cookie_path_fails_when_control_is_not_satisfied():
    result = evaluate({'session_path': 'unexpected'})
    assert result["status"] == "fail"
    assert result["id"] == "AG-020"
