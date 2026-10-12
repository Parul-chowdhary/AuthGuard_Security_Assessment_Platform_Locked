from app.security_controls import evaluate_all_controls


def test_registry_runs_all_controls_in_stable_order():
    results = evaluate_all_controls({})
    assert len(results) == 80
    ids = [item["id"] for item in results]
    assert ids == sorted(ids)
    assert all(item["status"] == "fail" for item in results)


def test_registry_never_makes_network_requests():
    # It accepts a plain observation mapping and evaluates only local rule modules.
    result = evaluate_all_controls({"password_min_length": 14})
    assert len(result) == 80
    assert result[27]["status"] == "pass"
