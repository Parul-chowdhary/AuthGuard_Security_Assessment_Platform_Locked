"""CORS origin is explicitly allowed."""
from app.security_controls import evaluate_spec

CONTROL = {'id': 'AG-014', 'name': 'cors_origin_allowlist', 'field': 'cors_origin_allowed', 'operator': 'truthy', 'expected': None, 'severity': 'medium', 'description': 'CORS origin is explicitly allowed.', 'pass_message': 'CORS origin is explicitly allowed.', 'fail_message': 'CORS origin is explicitly allowed. Control is not satisfied.'}

def evaluate(observation: dict) -> dict | None:
    """Evaluate CORS origin is explicitly allowed."""
    return evaluate_spec(CONTROL, observation)
