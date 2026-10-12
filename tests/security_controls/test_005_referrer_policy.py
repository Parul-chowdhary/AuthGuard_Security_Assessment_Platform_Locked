from app.security_controls.control_005_referrer_policy import evaluate

def test_referrer_policy_passes_when_control_is_satisfied():
    result = evaluate({'referrer_policy': 'no-referrer'})
    assert result["status"] == "pass"

def test_referrer_policy_fails_when_control_is_not_satisfied():
    result = evaluate({'referrer_policy': 'not-allowed'})
    assert result["status"] == "fail"
    assert result["id"] == "AG-005"
