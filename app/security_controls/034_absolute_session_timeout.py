"""An absolute session lifetime is configured."""
from app.security_controls import evaluate_spec

CONTROL = {'id': 'AG-034', 'name': 'absolute_session_timeout', 'field': 'session_absolute_timeout_minutes', 'operator': 'at_least', 'expected': 1, 'severity': 'medium', 'description': 'An absolute session lifetime is configured.', 'pass_message': 'An absolute session lifetime is configured.', 'fail_message': 'An absolute session lifetime is configured. Control is not satisfied.'}

def evaluate(observation: dict) -> dict | None:
    """Evaluate An absolute session lifetime is configured."""
    return evaluate_spec(CONTROL, observation)
