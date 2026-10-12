"""Logout invalidates the server-side session."""
from app.security_controls import evaluate_spec

CONTROL = {'id': 'AG-022', 'name': 'logout_invalidates_session', 'field': 'logout_invalidates_session', 'operator': 'truthy', 'expected': None, 'severity': 'high', 'description': 'Logout invalidates the server-side session.', 'pass_message': 'Logout invalidates the server-side session.', 'fail_message': 'Logout invalidates the server-side session. Control is not satisfied.'}

def evaluate(observation: dict) -> dict | None:
    """Evaluate Logout invalidates the server-side session."""
    return evaluate_spec(CONTROL, observation)
