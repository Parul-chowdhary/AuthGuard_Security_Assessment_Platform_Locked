from app.security_controls.control_007_cache_control_auth import evaluate

def test_cache_control_auth_passes_when_control_is_satisfied():
    result = evaluate({'cache_control_auth': 'prefix no-store suffix'})
    assert result["status"] == "pass"

def test_cache_control_auth_fails_when_control_is_not_satisfied():
    result = evaluate({'cache_control_auth': 'not-matching'})
    assert result["status"] == "fail"
    assert result["id"] == "AG-007"
