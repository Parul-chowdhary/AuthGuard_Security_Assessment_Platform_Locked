from app.security_controls.control_003_frame_ancestors import evaluate

def test_frame_ancestors_passes_when_control_is_satisfied():
    result = evaluate({'frame_ancestors': "prefix 'none' suffix"})
    assert result["status"] == "pass"

def test_frame_ancestors_fails_when_control_is_not_satisfied():
    result = evaluate({'frame_ancestors': 'not-matching'})
    assert result["status"] == "fail"
    assert result["id"] == "AG-003"
