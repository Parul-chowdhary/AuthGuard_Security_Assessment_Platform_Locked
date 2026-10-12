from app.security_controls.035_csrf_protection import evaluate

def test_csrf_protection_passes_when_control_is_satisfied():
    result = evaluate({'csrf_protection': True})
    assert result["status"] == "pass"

def test_csrf_protection_fails_when_control_is_not_satisfied():
    result = evaluate({'csrf_protection': False})
    assert result["status"] == "fail"
    assert result["id"] == "AG-035"
