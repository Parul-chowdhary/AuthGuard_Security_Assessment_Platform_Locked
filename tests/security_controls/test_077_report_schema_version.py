from app.security_controls.control_077_report_schema_version import evaluate

def test_report_schema_version_passes_when_control_is_satisfied():
    result = evaluate({'report_schema_version': 'present'})
    assert result["status"] == "pass"

def test_report_schema_version_fails_when_control_is_not_satisfied():
    result = evaluate({'report_schema_version': ''})
    assert result["status"] == "fail"
    assert result["id"] == "AG-077"
