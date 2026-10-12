from app.security_controls.015_tls_minimum_version import evaluate

def test_tls_minimum_version_passes_when_control_is_satisfied():
    result = evaluate({'tls_version': 'TLSv1.2'})
    assert result["status"] == "pass"

def test_tls_minimum_version_fails_when_control_is_not_satisfied():
    result = evaluate({'tls_version': 'not-allowed'})
    assert result["status"] == "fail"
    assert result["id"] == "AG-015"
