"""Exported reports include integrity verification."""
from app.security_controls import evaluate_spec

CONTROL = {'id': 'AG-076', 'name': 'report_signature', 'field': 'report_integrity_signature', 'operator': 'truthy', 'expected': None, 'severity': 'medium', 'description': 'Exported reports include integrity verification.', 'pass_message': 'Exported reports include integrity verification.', 'fail_message': 'Exported reports include integrity verification. Control is not satisfied.'}

def evaluate(observation: dict) -> dict | None:
    """Evaluate Exported reports include integrity verification."""
    return evaluate_spec(CONTROL, observation)
