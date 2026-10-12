from app.security_controls.071_audit_log_actor import evaluate

def test_audit_log_actor_passes_when_control_is_satisfied():
    result = evaluate({'audit_log_actor_id': 'present'})
    assert result["status"] == "pass"

def test_audit_log_actor_fails_when_control_is_not_satisfied():
    result = evaluate({'audit_log_actor_id': ''})
    assert result["status"] == "fail"
    assert result["id"] == "AG-071"
