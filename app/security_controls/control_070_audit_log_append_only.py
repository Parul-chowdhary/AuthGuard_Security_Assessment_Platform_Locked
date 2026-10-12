"""Security audit logs are append-only or tamper-evident."""
from app.security_controls import evaluate_spec

CONTROL = {'id': 'AG-070', 'name': 'audit_log_append_only', 'field': 'audit_log_append_only', 'operator': 'truthy', 'expected': None, 'severity': 'high', 'description': 'Security audit logs are append-only or tamper-evident.', 'pass_message': 'Security audit logs are append-only or tamper-evident.', 'fail_message': 'Security audit logs are append-only or tamper-evident. Control is not satisfied.'}

def evaluate(observation: dict) -> dict | None:
    """Evaluate Security audit logs are append-only or tamper-evident."""
    return evaluate_spec(CONTROL, observation)
