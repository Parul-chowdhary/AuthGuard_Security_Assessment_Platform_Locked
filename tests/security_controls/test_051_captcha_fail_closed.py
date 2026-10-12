from app.security_controls.control_051_captcha_fail_closed import evaluate

def test_captcha_fail_closed_passes_when_control_is_satisfied():
    result = evaluate({'captcha_provider_failure_mode': 'fail_closed'})
    assert result["status"] == "pass"

def test_captcha_fail_closed_fails_when_control_is_not_satisfied():
    result = evaluate({'captcha_provider_failure_mode': 'unexpected'})
    assert result["status"] == "fail"
    assert result["id"] == "AG-051"
