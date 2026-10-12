"""COEP is set."""
from app.security_controls import evaluate_spec

CONTROL = {'id': 'AG-010', 'name': 'cross_origin_embedder_policy', 'field': 'cross_origin_embedder_policy', 'operator': 'present', 'expected': None, 'severity': 'medium', 'description': 'COEP is set.', 'pass_message': 'COEP is set.', 'fail_message': 'COEP is set. Control is not satisfied.'}

def evaluate(observation: dict) -> dict | None:
    """Evaluate COEP is set."""
    return evaluate_spec(CONTROL, observation)
