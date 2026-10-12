"""Password reset invalidates active sessions."""
from app.security_controls import evaluate_spec

CONTROL = {'id': 'AG-023', 'name': 'password_reset_invalidates_sessions', 'field': 'password_reset_invalidates_sessions', 'operator': 'truthy', 'expected': None, 'severity': 'high', 'description': 'Password reset invalidates active sessions.', 'pass_message': 'Password reset invalidates active sessions.', 'fail_message': 'Password reset invalidates active sessions. Control is not satisfied.'}

def evaluate(observation: dict) -> dict | None:
    """Evaluate Password reset invalidates active sessions."""
    return evaluate_spec(CONTROL, observation)
