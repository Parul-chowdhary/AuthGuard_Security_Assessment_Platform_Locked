from app.security_controls.006_permissions_policy import evaluate

def test_permissions_policy_passes_when_control_is_satisfied():
    result = evaluate({'permissions_policy': 'present'})
    assert result["status"] == "pass"

def test_permissions_policy_fails_when_control_is_not_satisfied():
    result = evaluate({'permissions_policy': ''})
    assert result["status"] == "fail"
    assert result["id"] == "AG-006"
