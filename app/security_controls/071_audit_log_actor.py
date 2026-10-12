"""Audit events identify the acting principal."""
from app.security_controls import evaluate_spec

CONTROL = {'id': 'AG-071', 'name': 'audit_log_actor', 'field': 'audit_log_actor_id', 'operator': 'present', 'expected': None, 'severity': 'medium', 'description': 'Audit events identify the acting principal.', 'pass_message': 'Audit events identify the acting principal.', 'fail_message': 'Audit events identify the acting principal. Control is not satisfied.'}

def evaluate(observation: dict) -> dict | None:
    """Evaluate Audit events identify the acting principal."""
    return evaluate_spec(CONTROL, observation)
