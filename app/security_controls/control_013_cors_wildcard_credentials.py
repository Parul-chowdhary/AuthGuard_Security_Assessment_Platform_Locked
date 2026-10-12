"""Credentialed wildcard CORS is not enabled."""
from app.security_controls import evaluate_spec

CONTROL = {'id': 'AG-013', 'name': 'cors_wildcard_credentials', 'field': 'cors_wildcard_credentials', 'operator': 'falsy', 'expected': None, 'severity': 'medium', 'description': 'Credentialed wildcard CORS is not enabled.', 'pass_message': 'Credentialed wildcard CORS is not enabled.', 'fail_message': 'Credentialed wildcard CORS is not enabled. Control is not satisfied.'}

def evaluate(observation: dict) -> dict | None:
    """Evaluate Credentialed wildcard CORS is not enabled."""
    return evaluate_spec(CONTROL, observation)
