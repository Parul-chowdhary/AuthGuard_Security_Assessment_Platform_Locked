from app.security_controls.control_028_password_minimum_length import evaluate

def test_password_minimum_length_passes_when_control_is_satisfied():
    result = evaluate({'password_min_length': 12})
    assert result["status"] == "pass"

def test_password_minimum_length_fails_when_control_is_not_satisfied():
    result = evaluate({'password_min_length': 11})
    assert result["status"] == "fail"
    assert result["id"] == "AG-028"
