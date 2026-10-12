"""Findings state evidence confidence."""
from app.security_controls import evaluate_spec

CONTROL = {'id': 'AG-079', 'name': 'finding_confidence', 'field': 'finding_confidence', 'operator': 'one_of', 'expected': ['low', 'medium', 'high'], 'severity': 'low', 'description': 'Findings state evidence confidence.', 'pass_message': 'Findings state evidence confidence.', 'fail_message': 'Findings state evidence confidence. Control is not satisfied.'}

def evaluate(observation: dict) -> dict | None:
    """Evaluate Findings state evidence confidence."""
    return evaluate_spec(CONTROL, observation)
