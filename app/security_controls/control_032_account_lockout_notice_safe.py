"""Lockout message does not reveal internal account state."""
from app.security_controls import evaluate_spec

CONTROL = {'id': 'AG-032', 'name': 'account_lockout_notice_safe', 'field': 'lockout_notice_safe', 'operator': 'truthy', 'expected': None, 'severity': 'low', 'description': 'Lockout message does not reveal internal account state.', 'pass_message': 'Lockout message does not reveal internal account state.', 'fail_message': 'Lockout message does not reveal internal account state. Control is not satisfied.'}

def evaluate(observation: dict) -> dict | None:
    """Evaluate Lockout message does not reveal internal account state."""
    return evaluate_spec(CONTROL, observation)
