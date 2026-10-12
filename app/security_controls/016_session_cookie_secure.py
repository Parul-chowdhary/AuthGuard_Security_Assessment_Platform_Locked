"""Session cookie is Secure."""
from app.security_controls import evaluate_spec

CONTROL = {'id': 'AG-016', 'name': 'session_cookie_secure', 'field': 'session_secure', 'operator': 'truthy', 'expected': None, 'severity': 'high', 'description': 'Session cookie is Secure.', 'pass_message': 'Session cookie is Secure.', 'fail_message': 'Session cookie is Secure. Control is not satisfied.'}

def evaluate(observation: dict) -> dict | None:
    """Evaluate Session cookie is Secure."""
    return evaluate_spec(CONTROL, observation)
