from app.security_controls.control_055_retry_after_header import evaluate

def test_retry_after_header_passes_when_control_is_satisfied():
    result = evaluate({'retry_after_on_429': True})
    assert result["status"] == "pass"

def test_retry_after_header_fails_when_control_is_not_satisfied():
    result = evaluate({'retry_after_on_429': False})
    assert result["status"] == "fail"
    assert result["id"] == "AG-055"
