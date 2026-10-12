from app.security_controls.060_request_timeout import evaluate

def test_request_timeout_passes_when_control_is_satisfied():
    result = evaluate({'request_timeout_seconds': 1})
    assert result["status"] == "pass"

def test_request_timeout_fails_when_control_is_not_satisfied():
    result = evaluate({'request_timeout_seconds': 0})
    assert result["status"] == "fail"
    assert result["id"] == "AG-060"
