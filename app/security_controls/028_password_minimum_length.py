"""Password policy requires at least 12 characters."""
from app.security_controls import evaluate_spec

CONTROL = {'id': 'AG-028', 'name': 'password_minimum_length', 'field': 'password_min_length', 'operator': 'at_least', 'expected': 12, 'severity': 'medium', 'description': 'Password policy requires at least 12 characters.', 'pass_message': 'Password policy requires at least 12 characters.', 'fail_message': 'Password policy requires at least 12 characters. Control is not satisfied.'}

def evaluate(observation: dict) -> dict | None:
    """Evaluate Password policy requires at least 12 characters."""
    return evaluate_spec(CONTROL, observation)
