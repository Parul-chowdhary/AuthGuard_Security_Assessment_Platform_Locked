from app.security_controls.control_065_assessment_cancellation import evaluate

def test_assessment_cancellation_passes_when_control_is_satisfied():
    result = evaluate({'assessment_cancellation_supported': True})
    assert result["status"] == "pass"

def test_assessment_cancellation_fails_when_control_is_not_satisfied():
    result = evaluate({'assessment_cancellation_supported': False})
    assert result["status"] == "fail"
    assert result["id"] == "AG-065"
