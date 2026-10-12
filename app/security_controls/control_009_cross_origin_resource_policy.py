"""CORP is set."""
from app.security_controls import evaluate_spec

CONTROL = {'id': 'AG-009', 'name': 'cross_origin_resource_policy', 'field': 'cross_origin_resource_policy', 'operator': 'present', 'expected': None, 'severity': 'medium', 'description': 'CORP is set.', 'pass_message': 'CORP is set.', 'fail_message': 'CORP is set. Control is not satisfied.'}

def evaluate(observation: dict) -> dict | None:
    """Evaluate CORP is set."""
    return evaluate_spec(CONTROL, observation)
