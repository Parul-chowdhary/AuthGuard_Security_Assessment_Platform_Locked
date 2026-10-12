from app.security_controls.063_private_ip_block import evaluate

def test_private_ip_block_passes_when_control_is_satisfied():
    result = evaluate({'private_ip_blocking': True})
    assert result["status"] == "pass"

def test_private_ip_block_fails_when_control_is_not_satisfied():
    result = evaluate({'private_ip_blocking': False})
    assert result["status"] == "fail"
    assert result["id"] == "AG-063"
