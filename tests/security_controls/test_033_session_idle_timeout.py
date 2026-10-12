from app.security_controls.control_033_session_idle_timeout import evaluate

def test_session_idle_timeout_passes_when_control_is_satisfied():
    result = evaluate({'session_idle_timeout_minutes': 1})
    assert result["status"] == "pass"

def test_session_idle_timeout_fails_when_control_is_not_satisfied():
    result = evaluate({'session_idle_timeout_minutes': 0})
    assert result["status"] == "fail"
    assert result["id"] == "AG-033"
