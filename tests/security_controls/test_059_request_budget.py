from app.security_controls.059_request_budget import evaluate

def test_request_budget_passes_when_control_is_satisfied():
    result = evaluate({'request_budget_configured': True})
    assert result["status"] == "pass"

def test_request_budget_fails_when_control_is_not_satisfied():
    result = evaluate({'request_budget_configured': False})
    assert result["status"] == "fail"
    assert result["id"] == "AG-059"
