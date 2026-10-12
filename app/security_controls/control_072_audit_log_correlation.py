"""Audit events carry a correlation identifier."""
from app.security_controls import evaluate_spec

CONTROL = {'id': 'AG-072', 'name': 'audit_log_correlation', 'field': 'audit_correlation_id', 'operator': 'present', 'expected': None, 'severity': 'low', 'description': 'Audit events carry a correlation identifier.', 'pass_message': 'Audit events carry a correlation identifier.', 'fail_message': 'Audit events carry a correlation identifier. Control is not satisfied.'}

def evaluate(observation: dict) -> dict | None:
    """Evaluate Audit events carry a correlation identifier."""
    return evaluate_spec(CONTROL, observation)
