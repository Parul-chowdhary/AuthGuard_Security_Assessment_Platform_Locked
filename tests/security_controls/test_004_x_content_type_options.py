from app.security_controls.control_004_x_content_type_options import evaluate

def test_x_content_type_options_passes_when_control_is_satisfied():
    result = evaluate({'x_content_type_options': 'nosniff'})
    assert result["status"] == "pass"

def test_x_content_type_options_fails_when_control_is_not_satisfied():
    result = evaluate({'x_content_type_options': 'unexpected'})
    assert result["status"] == "fail"
    assert result["id"] == "AG-004"
