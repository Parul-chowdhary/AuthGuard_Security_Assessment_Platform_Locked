from app.security_controls.076_report_signature import evaluate

def test_report_signature_passes_when_control_is_satisfied():
    result = evaluate({'report_integrity_signature': True})
    assert result["status"] == "pass"

def test_report_signature_fails_when_control_is_not_satisfied():
    result = evaluate({'report_integrity_signature': False})
    assert result["status"] == "fail"
    assert result["id"] == "AG-076"
