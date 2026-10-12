from app.security_controls.049_captcha_replay_protection import evaluate

def test_captcha_replay_protection_passes_when_control_is_satisfied():
    result = evaluate({'captcha_replay_protection': True})
    assert result["status"] == "pass"

def test_captcha_replay_protection_fails_when_control_is_not_satisfied():
    result = evaluate({'captcha_replay_protection': False})
    assert result["status"] == "fail"
    assert result["id"] == "AG-049"
