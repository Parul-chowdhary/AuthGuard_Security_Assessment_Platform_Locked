from app.security_controls.066_evidence_secret_redaction import evaluate

def test_evidence_secret_redaction_passes_when_control_is_satisfied():
    result = evaluate({'evidence_secret_redaction': True})
    assert result["status"] == "pass"

def test_evidence_secret_redaction_fails_when_control_is_not_satisfied():
    result = evaluate({'evidence_secret_redaction': False})
    assert result["status"] == "fail"
    assert result["id"] == "AG-066"
