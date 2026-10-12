from app.security_controls.control_072_audit_log_correlation import evaluate

def test_audit_log_correlation_passes_when_control_is_satisfied():
    result = evaluate({'audit_correlation_id': 'present'})
    assert result["status"] == "pass"

def test_audit_log_correlation_fails_when_control_is_not_satisfied():
    result = evaluate({'audit_correlation_id': ''})
    assert result["status"] == "fail"
    assert result["id"] == "AG-072"
