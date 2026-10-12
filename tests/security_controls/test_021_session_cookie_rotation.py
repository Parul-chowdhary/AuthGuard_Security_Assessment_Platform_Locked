from app.security_controls.021_session_cookie_rotation import evaluate

def test_session_cookie_rotation_passes_when_control_is_satisfied():
    result = evaluate({'session_rotated_after_login': True})
    assert result["status"] == "pass"

def test_session_cookie_rotation_fails_when_control_is_not_satisfied():
    result = evaluate({'session_rotated_after_login': False})
    assert result["status"] == "fail"
    assert result["id"] == "AG-021"
