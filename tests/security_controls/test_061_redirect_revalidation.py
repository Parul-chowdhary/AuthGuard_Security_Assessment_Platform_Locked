from app.security_controls.061_redirect_revalidation import evaluate

def test_redirect_revalidation_passes_when_control_is_satisfied():
    result = evaluate({'redirects_revalidated': True})
    assert result["status"] == "pass"

def test_redirect_revalidation_fails_when_control_is_not_satisfied():
    result = evaluate({'redirects_revalidated': False})
    assert result["status"] == "fail"
    assert result["id"] == "AG-061"
