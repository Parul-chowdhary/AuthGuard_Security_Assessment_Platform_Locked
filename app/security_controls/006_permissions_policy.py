"""A Permissions-Policy header is present."""
from app.security_controls import evaluate_spec

CONTROL = {'id': 'AG-006', 'name': 'permissions_policy', 'field': 'permissions_policy', 'operator': 'present', 'expected': None, 'severity': 'medium', 'description': 'A Permissions-Policy header is present.', 'pass_message': 'A Permissions-Policy header is present.', 'fail_message': 'A Permissions-Policy header is present. Control is not satisfied.'}

def evaluate(observation: dict) -> dict | None:
    """Evaluate A Permissions-Policy header is present."""
    return evaluate_spec(CONTROL, observation)
