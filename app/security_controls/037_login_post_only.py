"""Credentials are not submitted in query strings."""
from app.security_controls import evaluate_spec

CONTROL = {'id': 'AG-037', 'name': 'login_post_only', 'field': 'login_method', 'operator': 'equals', 'expected': 'POST', 'severity': 'medium', 'description': 'Credentials are not submitted in query strings.', 'pass_message': 'Credentials are not submitted in query strings.', 'fail_message': 'Credentials are not submitted in query strings. Control is not satisfied.'}

def evaluate(observation: dict) -> dict | None:
    """Evaluate Credentials are not submitted in query strings."""
    return evaluate_spec(CONTROL, observation)
