from app.security_controls.010_cross_origin_embedder_policy import evaluate

def test_cross_origin_embedder_policy_passes_when_control_is_satisfied():
    result = evaluate({'cross_origin_embedder_policy': 'present'})
    assert result["status"] == "pass"

def test_cross_origin_embedder_policy_fails_when_control_is_not_satisfied():
    result = evaluate({'cross_origin_embedder_policy': ''})
    assert result["status"] == "fail"
    assert result["id"] == "AG-010"
