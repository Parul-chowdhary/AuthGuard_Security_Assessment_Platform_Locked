from app.security_controls.control_032_account_lockout_notice_safe import evaluate

def test_account_lockout_notice_safe_passes_when_control_is_satisfied():
    result = evaluate({'lockout_notice_safe': True})
    assert result["status"] == "pass"

def test_account_lockout_notice_safe_fails_when_control_is_not_satisfied():
    result = evaluate({'lockout_notice_safe': False})
    assert result["status"] == "fail"
    assert result["id"] == "AG-032"
