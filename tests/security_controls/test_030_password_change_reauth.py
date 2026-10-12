from app.security_controls.030_password_change_reauth import evaluate

def test_password_change_reauth_passes_when_control_is_satisfied():
    result = evaluate({'password_change_reauth': True})
    assert result["status"] == "pass"

def test_password_change_reauth_fails_when_control_is_not_satisfied():
    result = evaluate({'password_change_reauth': False})
    assert result["status"] == "fail"
    assert result["id"] == "AG-030"
