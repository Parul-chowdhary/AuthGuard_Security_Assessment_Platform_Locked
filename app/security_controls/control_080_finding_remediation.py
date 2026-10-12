"""Findings include actionable remediation."""
from app.security_controls import evaluate_spec

CONTROL = {'id': 'AG-080', 'name': 'finding_remediation', 'field': 'finding_remediation', 'operator': 'present', 'expected': None, 'severity': 'low', 'description': 'Findings include actionable remediation.', 'pass_message': 'Findings include actionable remediation.', 'fail_message': 'Findings include actionable remediation. Control is not satisfied.'}

def evaluate(observation: dict) -> dict | None:
    """Evaluate Findings include actionable remediation."""
    return evaluate_spec(CONTROL, observation)
