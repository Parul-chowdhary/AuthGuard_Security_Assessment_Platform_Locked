from app.security_controls.control_074_report_includes_scope import evaluate

def test_report_includes_scope_passes_when_control_is_satisfied():
    result = evaluate({'report_scope_included': True})
    assert result["status"] == "pass"

def test_report_includes_scope_fails_when_control_is_not_satisfied():
    result = evaluate({'report_scope_included': False})
    assert result["status"] == "fail"
    assert result["id"] == "AG-074"
