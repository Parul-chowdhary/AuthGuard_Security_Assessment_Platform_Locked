from app.security_controls.036_origin_check import evaluate

def test_origin_check_passes_when_control_is_satisfied():
    result = evaluate({'origin_check_enabled': True})
    assert result["status"] == "pass"

def test_origin_check_fails_when_control_is_not_satisfied():
    result = evaluate({'origin_check_enabled': False})
    assert result["status"] == "fail"
    assert result["id"] == "AG-036"
