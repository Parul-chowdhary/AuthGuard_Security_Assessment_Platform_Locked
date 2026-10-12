from app.security_controls.control_047_captcha_server_validation import evaluate

def test_captcha_server_validation_passes_when_control_is_satisfied():
    result = evaluate({'captcha_server_side_validation': True})
    assert result["status"] == "pass"

def test_captcha_server_validation_fails_when_control_is_not_satisfied():
    result = evaluate({'captcha_server_side_validation': False})
    assert result["status"] == "fail"
    assert result["id"] == "AG-047"
