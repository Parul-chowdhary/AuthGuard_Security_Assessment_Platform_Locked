"""Passwords are excluded from logs."""
from app.security_controls import evaluate_spec

CONTROL = {'id': 'AG-038', 'name': 'password_not_logged', 'field': 'password_logging_disabled', 'operator': 'truthy', 'expected': None, 'severity': 'high', 'description': 'Passwords are excluded from logs.', 'pass_message': 'Passwords are excluded from logs.', 'fail_message': 'Passwords are excluded from logs. Control is not satisfied.'}

def evaluate(observation: dict) -> dict | None:
    """Evaluate Passwords are excluded from logs."""
    return evaluate_spec(CONTROL, observation)
