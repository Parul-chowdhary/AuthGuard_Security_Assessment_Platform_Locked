"""Session cookie is HttpOnly."""
from app.security_controls import evaluate_spec

CONTROL = {'id': 'AG-017', 'name': 'session_cookie_httponly', 'field': 'session_httponly', 'operator': 'truthy', 'expected': None, 'severity': 'high', 'description': 'Session cookie is HttpOnly.', 'pass_message': 'Session cookie is HttpOnly.', 'fail_message': 'Session cookie is HttpOnly. Control is not satisfied.'}

def evaluate(observation: dict) -> dict | None:
    """Evaluate Session cookie is HttpOnly."""
    return evaluate_spec(CONTROL, observation)
