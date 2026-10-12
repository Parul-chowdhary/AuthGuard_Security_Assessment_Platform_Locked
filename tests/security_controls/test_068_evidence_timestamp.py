from app.security_controls.control_068_evidence_timestamp import evaluate

def test_evidence_timestamp_passes_when_control_is_satisfied():
    result = evaluate({'evidence_timestamp_utc': 'present'})
    assert result["status"] == "pass"

def test_evidence_timestamp_fails_when_control_is_not_satisfied():
    result = evaluate({'evidence_timestamp_utc': ''})
    assert result["status"] == "fail"
    assert result["id"] == "AG-068"
