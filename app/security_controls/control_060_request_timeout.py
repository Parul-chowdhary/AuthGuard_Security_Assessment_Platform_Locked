"""Outbound requests have a bounded timeout."""
from app.security_controls import evaluate_spec

CONTROL = {'id': 'AG-060', 'name': 'request_timeout', 'field': 'request_timeout_seconds', 'operator': 'at_least', 'expected': 1, 'severity': 'medium', 'description': 'Outbound requests have a bounded timeout.', 'pass_message': 'Outbound requests have a bounded timeout.', 'fail_message': 'Outbound requests have a bounded timeout. Control is not satisfied.'}

def evaluate(observation: dict) -> dict | None:
    """Evaluate Outbound requests have a bounded timeout."""
    return evaluate_spec(CONTROL, observation)
