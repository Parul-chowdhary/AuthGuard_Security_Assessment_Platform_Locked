"""Evidence has a SHA-256 integrity digest."""
from app.security_controls import evaluate_spec

CONTROL = {'id': 'AG-067', 'name': 'evidence_integrity_hash', 'field': 'evidence_sha256_present', 'operator': 'truthy', 'expected': None, 'severity': 'medium', 'description': 'Evidence has a SHA-256 integrity digest.', 'pass_message': 'Evidence has a SHA-256 integrity digest.', 'fail_message': 'Evidence has a SHA-256 integrity digest. Control is not satisfied.'}

def evaluate(observation: dict) -> dict | None:
    """Evaluate Evidence has a SHA-256 integrity digest."""
    return evaluate_spec(CONTROL, observation)
