"""Evidence is redacted before persistence."""
from app.security_controls import evaluate_spec

CONTROL = {'id': 'AG-066', 'name': 'evidence_secret_redaction', 'field': 'evidence_secret_redaction', 'operator': 'truthy', 'expected': None, 'severity': 'high', 'description': 'Evidence is redacted before persistence.', 'pass_message': 'Evidence is redacted before persistence.', 'fail_message': 'Evidence is redacted before persistence. Control is not satisfied.'}

def evaluate(observation: dict) -> dict | None:
    """Evaluate Evidence is redacted before persistence."""
    return evaluate_spec(CONTROL, observation)
