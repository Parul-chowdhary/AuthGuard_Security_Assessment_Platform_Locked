"""Privileged accounts require MFA."""
from app.security_controls import evaluate_spec

CONTROL = {'id': 'AG-026', 'name': 'mfa_required_privileged', 'field': 'mfa_required_privileged', 'operator': 'truthy', 'expected': None, 'severity': 'high', 'description': 'Privileged accounts require MFA.', 'pass_message': 'Privileged accounts require MFA.', 'fail_message': 'Privileged accounts require MFA. Control is not satisfied.'}

def evaluate(observation: dict) -> dict | None:
    """Evaluate Privileged accounts require MFA."""
    return evaluate_spec(CONTROL, observation)
