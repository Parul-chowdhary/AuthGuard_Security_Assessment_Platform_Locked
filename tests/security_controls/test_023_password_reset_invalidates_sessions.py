from app.security_controls.control_023_password_reset_invalidates_sessions import evaluate

def test_password_reset_invalidates_sessions_passes_when_control_is_satisfied():
    result = evaluate({'password_reset_invalidates_sessions': True})
    assert result["status"] == "pass"

def test_password_reset_invalidates_sessions_fails_when_control_is_not_satisfied():
    result = evaluate({'password_reset_invalidates_sessions': False})
    assert result["status"] == "fail"
    assert result["id"] == "AG-023"
