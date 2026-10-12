from app.security_controls.002_strict_transport_security import evaluate

def test_strict_transport_security_passes_when_control_is_satisfied():
    result = evaluate({'strict_transport_security': 'present'})
    assert result["status"] == "pass"

def test_strict_transport_security_fails_when_control_is_not_satisfied():
    result = evaluate({'strict_transport_security': ''})
    assert result["status"] == "fail"
    assert result["id"] == "AG-002"
