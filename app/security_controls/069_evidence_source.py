"""Evidence records its source endpoint."""
from app.security_controls import evaluate_spec

CONTROL = {'id': 'AG-069', 'name': 'evidence_source', 'field': 'evidence_source_url', 'operator': 'present', 'expected': None, 'severity': 'low', 'description': 'Evidence records its source endpoint.', 'pass_message': 'Evidence records its source endpoint.', 'fail_message': 'Evidence records its source endpoint. Control is not satisfied.'}

def evaluate(observation: dict) -> dict | None:
    """Evaluate Evidence records its source endpoint."""
    return evaluate_spec(CONTROL, observation)
