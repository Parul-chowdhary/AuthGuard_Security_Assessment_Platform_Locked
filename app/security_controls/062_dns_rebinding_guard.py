"""Resolved destinations are rechecked to reduce DNS rebinding risk."""
from app.security_controls import evaluate_spec

CONTROL = {'id': 'AG-062', 'name': 'dns_rebinding_guard', 'field': 'dns_rebinding_guard', 'operator': 'truthy', 'expected': None, 'severity': 'high', 'description': 'Resolved destinations are rechecked to reduce DNS rebinding risk.', 'pass_message': 'Resolved destinations are rechecked to reduce DNS rebinding risk.', 'fail_message': 'Resolved destinations are rechecked to reduce DNS rebinding risk. Control is not satisfied.'}

def evaluate(observation: dict) -> dict | None:
    """Evaluate Resolved destinations are rechecked to reduce DNS rebinding risk."""
    return evaluate_spec(CONTROL, observation)
