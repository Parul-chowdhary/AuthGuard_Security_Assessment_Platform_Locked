"""Evidence records a UTC timestamp."""
from app.security_controls import evaluate_spec

CONTROL = {'id': 'AG-068', 'name': 'evidence_timestamp', 'field': 'evidence_timestamp_utc', 'operator': 'present', 'expected': None, 'severity': 'low', 'description': 'Evidence records a UTC timestamp.', 'pass_message': 'Evidence records a UTC timestamp.', 'fail_message': 'Evidence records a UTC timestamp. Control is not satisfied.'}

def evaluate(observation: dict) -> dict | None:
    """Evaluate Evidence records a UTC timestamp."""
    return evaluate_spec(CONTROL, observation)
