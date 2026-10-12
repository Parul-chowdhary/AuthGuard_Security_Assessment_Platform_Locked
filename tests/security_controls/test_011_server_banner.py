from app.security_controls.control_011_server_banner import evaluate

def test_server_banner_passes_when_control_is_satisfied():
    result = evaluate({'server_banner': False})
    assert result["status"] == "pass"

def test_server_banner_fails_when_control_is_not_satisfied():
    result = evaluate({'server_banner': True})
    assert result["status"] == "fail"
    assert result["id"] == "AG-011"
