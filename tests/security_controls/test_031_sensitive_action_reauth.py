from app.security_controls.control_031_sensitive_action_reauth import evaluate

def test_sensitive_action_reauth_passes_when_control_is_satisfied():
    result = evaluate({'sensitive_action_reauth': True})
    assert result["status"] == "pass"

def test_sensitive_action_reauth_fails_when_control_is_not_satisfied():
    result = evaluate({'sensitive_action_reauth': False})
    assert result["status"] == "fail"
    assert result["id"] == "AG-031"
