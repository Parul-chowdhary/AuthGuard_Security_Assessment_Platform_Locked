from app.security_controls.control_056_distributed_rate_limit import evaluate

def test_distributed_rate_limit_passes_when_control_is_satisfied():
    result = evaluate({'rate_limit_shared_store': True})
    assert result["status"] == "pass"

def test_distributed_rate_limit_fails_when_control_is_not_satisfied():
    result = evaluate({'rate_limit_shared_store': False})
    assert result["status"] == "fail"
    assert result["id"] == "AG-056"
