from app.security_controls.control_050_captcha_provider_timeout import evaluate

def test_captcha_provider_timeout_passes_when_control_is_satisfied():
    result = evaluate({'captcha_provider_timeout_seconds': 1})
    assert result["status"] == "pass"

def test_captcha_provider_timeout_fails_when_control_is_not_satisfied():
    result = evaluate({'captcha_provider_timeout_seconds': 0})
    assert result["status"] == "fail"
    assert result["id"] == "AG-050"
