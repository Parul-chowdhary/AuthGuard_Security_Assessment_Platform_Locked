from app.security_controls.control_075_report_includes_limitations import evaluate

def test_report_includes_limitations_passes_when_control_is_satisfied():
    result = evaluate({'report_limitations_included': True})
    assert result["status"] == "pass"

def test_report_includes_limitations_fails_when_control_is_not_satisfied():
    result = evaluate({'report_limitations_included': False})
    assert result["status"] == "fail"
    assert result["id"] == "AG-075"
