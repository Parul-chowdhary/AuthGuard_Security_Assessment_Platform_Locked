"""Sensitive actions require step-up authentication."""
from app.security_controls import evaluate_spec

CONTROL = {'id': 'AG-031', 'name': 'sensitive_action_reauth', 'field': 'sensitive_action_reauth', 'operator': 'truthy', 'expected': None, 'severity': 'high', 'description': 'Sensitive actions require step-up authentication.', 'pass_message': 'Sensitive actions require step-up authentication.', 'fail_message': 'Sensitive actions require step-up authentication. Control is not satisfied.'}

def evaluate(observation: dict) -> dict | None:
    """Evaluate Sensitive actions require step-up authentication."""
    return evaluate_spec(CONTROL, observation)
