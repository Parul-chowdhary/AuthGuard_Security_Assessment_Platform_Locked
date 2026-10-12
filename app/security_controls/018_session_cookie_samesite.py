"""Session cookie has a restrictive SameSite policy."""
from app.security_controls import evaluate_spec

CONTROL = {'id': 'AG-018', 'name': 'session_cookie_samesite', 'field': 'session_samesite', 'operator': 'one_of', 'expected': ['Lax', 'Strict'], 'severity': 'high', 'description': 'Session cookie has a restrictive SameSite policy.', 'pass_message': 'Session cookie has a restrictive SameSite policy.', 'fail_message': 'Session cookie has a restrictive SameSite policy. Control is not satisfied.'}

def evaluate(observation: dict) -> dict | None:
    """Evaluate Session cookie has a restrictive SameSite policy."""
    return evaluate_spec(CONTROL, observation)
