"""A Content-Security-Policy header is present."""
from app.security_controls import evaluate_spec

CONTROL = {'id': 'AG-001', 'name': 'content_security_policy', 'field': 'content_security_policy', 'operator': 'present', 'expected': None, 'severity': 'medium', 'description': 'A Content-Security-Policy header is present.', 'pass_message': 'A Content-Security-Policy header is present.', 'fail_message': 'A Content-Security-Policy header is present. Control is not satisfied.'}

def evaluate(observation: dict) -> dict | None:
    """Evaluate A Content-Security-Policy header is present."""
    return evaluate_spec(CONTROL, observation)
