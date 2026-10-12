"""An idle session timeout is configured."""
from app.security_controls import evaluate_spec

CONTROL = {'id': 'AG-033', 'name': 'session_idle_timeout', 'field': 'session_idle_timeout_minutes', 'operator': 'at_least', 'expected': 1, 'severity': 'medium', 'description': 'An idle session timeout is configured.', 'pass_message': 'An idle session timeout is configured.', 'fail_message': 'An idle session timeout is configured. Control is not satisfied.'}

def evaluate(observation: dict) -> dict | None:
    """Evaluate An idle session timeout is configured."""
    return evaluate_spec(CONTROL, observation)
