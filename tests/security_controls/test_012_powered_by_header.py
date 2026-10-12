from app.security_controls.012_powered_by_header import evaluate

def test_powered_by_header_passes_when_control_is_satisfied():
    result = evaluate({'x_powered_by': False})
    assert result["status"] == "pass"

def test_powered_by_header_fails_when_control_is_not_satisfied():
    result = evaluate({'x_powered_by': True})
    assert result["status"] == "fail"
    assert result["id"] == "AG-012"
