from app.security_controls.control_037_login_post_only import evaluate

def test_login_post_only_passes_when_control_is_satisfied():
    result = evaluate({'login_method': 'POST'})
    assert result["status"] == "pass"

def test_login_post_only_fails_when_control_is_not_satisfied():
    result = evaluate({'login_method': 'unexpected'})
    assert result["status"] == "fail"
    assert result["id"] == "AG-037"
