"""Session cookie avoids unnecessarily broad Domain scope."""
from app.security_controls import evaluate_spec

CONTROL = {'id': 'AG-019', 'name': 'session_cookie_no_domain', 'field': 'session_domain', 'operator': 'falsy', 'expected': None, 'severity': 'high', 'description': 'Session cookie avoids unnecessarily broad Domain scope.', 'pass_message': 'Session cookie avoids unnecessarily broad Domain scope.', 'fail_message': 'Session cookie avoids unnecessarily broad Domain scope. Control is not satisfied.'}

def evaluate(observation: dict) -> dict | None:
    """Evaluate Session cookie avoids unnecessarily broad Domain scope."""
    return evaluate_spec(CONTROL, observation)
