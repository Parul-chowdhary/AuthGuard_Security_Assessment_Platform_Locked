"""COOP is set."""
from app.security_controls import evaluate_spec

CONTROL = {'id': 'AG-008', 'name': 'cross_origin_opener_policy', 'field': 'cross_origin_opener_policy', 'operator': 'present', 'expected': None, 'severity': 'medium', 'description': 'COOP is set.', 'pass_message': 'COOP is set.', 'fail_message': 'COOP is set. Control is not satisfied.'}

def evaluate(observation: dict) -> dict | None:
    """Evaluate COOP is set."""
    return evaluate_spec(CONTROL, observation)
