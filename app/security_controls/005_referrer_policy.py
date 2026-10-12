"""Referrer policy is restrictive."""
from app.security_controls import evaluate_spec

CONTROL = {'id': 'AG-005', 'name': 'referrer_policy', 'field': 'referrer_policy', 'operator': 'one_of', 'expected': ['no-referrer', 'strict-origin', 'strict-origin-when-cross-origin'], 'severity': 'medium', 'description': 'Referrer policy is restrictive.', 'pass_message': 'Referrer policy is restrictive.', 'fail_message': 'Referrer policy is restrictive. Control is not satisfied.'}

def evaluate(observation: dict) -> dict | None:
    """Evaluate Referrer policy is restrictive."""
    return evaluate_spec(CONTROL, observation)
