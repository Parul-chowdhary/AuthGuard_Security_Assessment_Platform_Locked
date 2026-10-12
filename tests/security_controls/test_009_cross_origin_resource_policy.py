from app.security_controls.009_cross_origin_resource_policy import evaluate

def test_cross_origin_resource_policy_passes_when_control_is_satisfied():
    result = evaluate({'cross_origin_resource_policy': 'present'})
    assert result["status"] == "pass"

def test_cross_origin_resource_policy_fails_when_control_is_not_satisfied():
    result = evaluate({'cross_origin_resource_policy': ''})
    assert result["status"] == "fail"
    assert result["id"] == "AG-009"
