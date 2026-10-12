from app.security_controls.029_password_breach_check import evaluate

def test_password_breach_check_passes_when_control_is_satisfied():
    result = evaluate({'password_breach_check': True})
    assert result["status"] == "pass"

def test_password_breach_check_fails_when_control_is_not_satisfied():
    result = evaluate({'password_breach_check': False})
    assert result["status"] == "fail"
    assert result["id"] == "AG-029"
