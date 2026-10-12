from app.security_controls.022_logout_invalidates_session import evaluate

def test_logout_invalidates_session_passes_when_control_is_satisfied():
    result = evaluate({'logout_invalidates_session': True})
    assert result["status"] == "pass"

def test_logout_invalidates_session_fails_when_control_is_not_satisfied():
    result = evaluate({'logout_invalidates_session': False})
    assert result["status"] == "fail"
    assert result["id"] == "AG-022"
