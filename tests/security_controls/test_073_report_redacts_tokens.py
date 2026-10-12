from app.security_controls.073_report_redacts_tokens import evaluate

def test_report_redacts_tokens_passes_when_control_is_satisfied():
    result = evaluate({'report_token_redaction': True})
    assert result["status"] == "pass"

def test_report_redacts_tokens_fails_when_control_is_not_satisfied():
    result = evaluate({'report_token_redaction': False})
    assert result["status"] == "fail"
    assert result["id"] == "AG-073"
