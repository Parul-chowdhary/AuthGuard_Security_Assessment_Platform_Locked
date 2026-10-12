"""Declarative authentication-security response controls.

Each control evaluates an observation supplied by a controlled test fixture or an
authorized assessment. Controls never send traffic themselves.
"""
from __future__ import annotations
from typing import Any

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
    checks = {
        "present": exists and actual is not None and actual != "",
        "equals": exists and actual == expected,
        "truthy": bool(actual),
        "falsy": not bool(actual),
        "contains": exists and expected in actual if actual is not None else False,
        "not_contains": exists and expected not in actual if actual is not None else False,
        "at_least": isinstance(actual, (int, float)) and actual >= expected,
        "one_of": exists and actual in expected,
    }
    if op not in checks:
        raise ValueError(f"Unsupported control operator: {op}")
    passed = checks[op]
    if passed:
        return {"id": spec["id"], "status": "pass", "severity": spec["severity"],
                "message": spec["pass_message"]}
    return {"id": spec["id"], "status": "fail", "severity": spec["severity"],
            "message": spec["fail_message"], "field": key, "observed": actual}
