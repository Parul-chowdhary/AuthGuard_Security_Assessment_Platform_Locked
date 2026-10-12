from app.security_controls.001_content_security_policy import evaluate

def test_content_security_policy_passes_when_control_is_satisfied():
    result = evaluate({'content_security_policy': 'present'})
    assert result["status"] == "pass"

def test_content_security_policy_fails_when_control_is_not_satisfied():
    result = evaluate({'content_security_policy': ''})
    assert result["status"] == "fail"
    assert result["id"] == "AG-001"
