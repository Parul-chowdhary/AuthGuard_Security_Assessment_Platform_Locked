from app.security_controls.control_014_cors_origin_allowlist import evaluate

def test_cors_origin_allowlist_passes_when_control_is_satisfied():
    result = evaluate({'cors_origin_allowed': True})
    assert result["status"] == "pass"

def test_cors_origin_allowlist_fails_when_control_is_not_satisfied():
    result = evaluate({'cors_origin_allowed': False})
    assert result["status"] == "fail"
    assert result["id"] == "AG-014"
