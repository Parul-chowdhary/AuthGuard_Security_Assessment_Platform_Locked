from app.security_controls.008_cross_origin_opener_policy import evaluate

def test_cross_origin_opener_policy_passes_when_control_is_satisfied():
    result = evaluate({'cross_origin_opener_policy': 'present'})
    assert result["status"] == "pass"

def test_cross_origin_opener_policy_fails_when_control_is_not_satisfied():
    result = evaluate({'cross_origin_opener_policy': ''})
    assert result["status"] == "fail"
    assert result["id"] == "AG-008"
