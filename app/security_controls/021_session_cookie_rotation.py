"""Session identifier rotates after login."""
from app.security_controls import evaluate_spec

CONTROL = {'id': 'AG-021', 'name': 'session_cookie_rotation', 'field': 'session_rotated_after_login', 'operator': 'truthy', 'expected': None, 'severity': 'high', 'description': 'Session identifier rotates after login.', 'pass_message': 'Session identifier rotates after login.', 'fail_message': 'Session identifier rotates after login. Control is not satisfied.'}

def evaluate(observation: dict) -> dict | None:
    """Evaluate Session identifier rotates after login."""
    return evaluate_spec(CONTROL, observation)
