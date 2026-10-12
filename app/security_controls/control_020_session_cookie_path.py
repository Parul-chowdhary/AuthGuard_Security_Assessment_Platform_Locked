"""Session cookie path is explicit."""
from app.security_controls import evaluate_spec

CONTROL = {'id': 'AG-020', 'name': 'session_cookie_path', 'field': 'session_path', 'operator': 'equals', 'expected': '/', 'severity': 'high', 'description': 'Session cookie path is explicit.', 'pass_message': 'Session cookie path is explicit.', 'fail_message': 'Session cookie path is explicit. Control is not satisfied.'}

def evaluate(observation: dict) -> dict | None:
    """Evaluate Session cookie path is explicit."""
    return evaluate_spec(CONTROL, observation)
