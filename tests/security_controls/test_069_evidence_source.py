from app.security_controls.control_069_evidence_source import evaluate

def test_evidence_source_passes_when_control_is_satisfied():
    result = evaluate({'evidence_source_url': 'present'})
    assert result["status"] == "pass"

def test_evidence_source_fails_when_control_is_not_satisfied():
    result = evaluate({'evidence_source_url': ''})
    assert result["status"] == "fail"
    assert result["id"] == "AG-069"
