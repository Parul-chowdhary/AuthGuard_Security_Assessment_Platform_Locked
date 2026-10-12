from app.security_controls.control_070_audit_log_append_only import evaluate

def test_audit_log_append_only_passes_when_control_is_satisfied():
    result = evaluate({'audit_log_append_only': True})
    assert result["status"] == "pass"

def test_audit_log_append_only_fails_when_control_is_not_satisfied():
    result = evaluate({'audit_log_append_only': False})
    assert result["status"] == "fail"
    assert result["id"] == "AG-070"
