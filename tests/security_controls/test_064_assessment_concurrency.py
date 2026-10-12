from app.security_controls.control_064_assessment_concurrency import evaluate

def test_assessment_concurrency_passes_when_control_is_satisfied():
    result = evaluate({'assessment_concurrency_limit': 1})
    assert result["status"] == "pass"

def test_assessment_concurrency_fails_when_control_is_not_satisfied():
    result = evaluate({'assessment_concurrency_limit': 0})
    assert result["status"] == "fail"
    assert result["id"] == "AG-064"
