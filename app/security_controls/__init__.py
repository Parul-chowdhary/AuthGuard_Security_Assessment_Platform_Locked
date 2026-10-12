"""Declarative authentication-security response controls.

Each control evaluates an observation supplied by a controlled test fixture or an
authorized assessment. Controls never send traffic themselves.
"""
from __future__ import annotations
from typing import Any
from importlib import import_module
from pathlib import Path

def evaluate_spec(spec: dict[str, Any], observation: dict[str, Any]) -> dict[str, Any] | None:
    """Evaluate one declarative control against a captured observation.

    Supported operators are equals, truthy, falsy, contains, not_contains,
    at_least, one_of, and present. Missing evidence fails closed for required
    fields and is reported as inconclusive when a spec sets allow_missing.
    """
    key = spec["field"]
    exists = key in observation
    actual = observation.get(key)
    if not exists and spec.get("allow_missing", False):
        return {"id": spec["id"], "status": "inconclusive",
                "severity": spec["severity"], "message": f"No evidence supplied for {key}."}
    op, expected = spec["operator"], spec.get("expected")
    if op == "present":
        passed = exists and actual is not None and actual != ""
    elif op == "equals":
        passed = exists and actual == expected
    elif op == "truthy":
        passed = bool(actual)
    elif op == "falsy":
        passed = exists and not bool(actual)
    elif op == "contains":
        passed = exists and actual is not None and expected in actual
    elif op == "not_contains":
        passed = exists and actual is not None and expected not in actual
    elif op == "at_least":
        passed = isinstance(actual, (int, float)) and not isinstance(actual, bool) and actual >= expected
    elif op == "one_of":
        passed = exists and actual in expected
    else:
        raise ValueError(f"Unsupported control operator: {op}")
    if passed:
        return {"id": spec["id"], "status": "pass", "severity": spec["severity"],
                "message": spec["pass_message"]}
    return {"id": spec["id"], "status": "fail", "severity": spec["severity"],
            "message": spec["fail_message"], "field": key, "observed": actual}


def evaluate_all_controls(observation: dict[str, Any]) -> list[dict[str, Any]]:
    """Run every registered control against one captured observation.

    This loader only evaluates supplied data; it does not make network requests.
    Control modules are imported in stable filename order for reproducible reports.
    """
    package_dir = Path(__file__).parent
    results: list[dict[str, Any]] = []
    for module_path in sorted(package_dir.glob("control_*.py")):
        module = import_module(f"{__name__}.{module_path.stem}")
        result = module.evaluate(observation)
        if result is not None:
            results.append(result)
    return results
