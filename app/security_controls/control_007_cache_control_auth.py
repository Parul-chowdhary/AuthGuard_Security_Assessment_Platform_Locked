"""Authentication responses are not cached."""
from app.security_controls import evaluate_spec

CONTROL = {'id': 'AG-007', 'name': 'cache_control_auth', 'field': 'cache_control_auth', 'operator': 'contains', 'expected': 'no-store', 'severity': 'medium', 'description': 'Authentication responses are not cached.', 'pass_message': 'Authentication responses are not cached.', 'fail_message': 'Authentication responses are not cached. Control is not satisfied.'}

def evaluate(observation: dict) -> dict | None:
    """Evaluate Authentication responses are not cached."""
    return evaluate_spec(CONTROL, observation)
