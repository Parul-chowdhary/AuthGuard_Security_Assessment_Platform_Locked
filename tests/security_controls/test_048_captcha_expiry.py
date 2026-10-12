from app.security_controls.048_captcha_expiry import evaluate

def test_captcha_expiry_passes_when_control_is_satisfied():
    result = evaluate({'captcha_expiry_enforced': True})
    assert result["status"] == "pass"

def test_captcha_expiry_fails_when_control_is_not_satisfied():
    result = evaluate({'captcha_expiry_enforced': False})
    assert result["status"] == "fail"
    assert result["id"] == "AG-048"
