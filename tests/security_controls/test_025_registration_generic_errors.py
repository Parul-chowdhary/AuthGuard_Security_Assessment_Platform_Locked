from app.security_controls.025_registration_generic_errors import evaluate

def test_registration_generic_errors_passes_when_control_is_satisfied():
    result = evaluate({'registration_generic_errors': True})
    assert result["status"] == "pass"

def test_registration_generic_errors_fails_when_control_is_not_satisfied():
    result = evaluate({'registration_generic_errors': False})
    assert result["status"] == "fail"
    assert result["id"] == "AG-025"
