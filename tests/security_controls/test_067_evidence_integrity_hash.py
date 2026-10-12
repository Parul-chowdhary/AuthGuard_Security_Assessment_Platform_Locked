from app.security_controls.067_evidence_integrity_hash import evaluate

def test_evidence_integrity_hash_passes_when_control_is_satisfied():
    result = evaluate({'evidence_sha256_present': True})
    assert result["status"] == "pass"

def test_evidence_integrity_hash_fails_when_control_is_not_satisfied():
    result = evaluate({'evidence_sha256_present': False})
    assert result["status"] == "fail"
    assert result["id"] == "AG-067"
