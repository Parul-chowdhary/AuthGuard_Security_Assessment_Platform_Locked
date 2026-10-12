from app.security_controls.057_rate_limit_key_privacy import evaluate

def test_rate_limit_key_privacy_passes_when_control_is_satisfied():
    result = evaluate({'rate_limit_key_hashed': True})
    assert result["status"] == "pass"

def test_rate_limit_key_privacy_fails_when_control_is_not_satisfied():
    result = evaluate({'rate_limit_key_hashed': False})
    assert result["status"] == "fail"
    assert result["id"] == "AG-057"
