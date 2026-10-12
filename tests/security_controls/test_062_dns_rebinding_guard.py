from app.security_controls.control_062_dns_rebinding_guard import evaluate

def test_dns_rebinding_guard_passes_when_control_is_satisfied():
    result = evaluate({'dns_rebinding_guard': True})
    assert result["status"] == "pass"

def test_dns_rebinding_guard_fails_when_control_is_not_satisfied():
    result = evaluate({'dns_rebinding_guard': False})
    assert result["status"] == "fail"
    assert result["id"] == "AG-062"
