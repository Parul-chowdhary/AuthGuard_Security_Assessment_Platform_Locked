from app.security_controls.058_circuit_breaker import evaluate

def test_circuit_breaker_passes_when_control_is_satisfied():
    result = evaluate({'circuit_breaker_enabled': True})
    assert result["status"] == "pass"

def test_circuit_breaker_fails_when_control_is_not_satisfied():
    result = evaluate({'circuit_breaker_enabled': False})
    assert result["status"] == "fail"
    assert result["id"] == "AG-058"
