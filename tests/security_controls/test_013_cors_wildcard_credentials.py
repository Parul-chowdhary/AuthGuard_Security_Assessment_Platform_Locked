from app.security_controls.013_cors_wildcard_credentials import evaluate

def test_cors_wildcard_credentials_passes_when_control_is_satisfied():
    result = evaluate({'cors_wildcard_credentials': False})
    assert result["status"] == "pass"

def test_cors_wildcard_credentials_fails_when_control_is_not_satisfied():
    result = evaluate({'cors_wildcard_credentials': True})
    assert result["status"] == "fail"
    assert result["id"] == "AG-013"
