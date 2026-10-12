"""Findings use a controlled severity vocabulary."""
from app.security_controls import evaluate_spec

CONTROL = {'id': 'AG-078', 'name': 'finding_severity', 'field': 'finding_severity', 'operator': 'one_of', 'expected': ['info', 'low', 'medium', 'high', 'critical'], 'severity': 'medium', 'description': 'Findings use a controlled severity vocabulary.', 'pass_message': 'Findings use a controlled severity vocabulary.', 'fail_message': 'Findings use a controlled severity vocabulary. Control is not satisfied.'}

def evaluate(observation: dict) -> dict | None:
    """Evaluate Findings use a controlled severity vocabulary."""
    return evaluate_spec(CONTROL, observation)
