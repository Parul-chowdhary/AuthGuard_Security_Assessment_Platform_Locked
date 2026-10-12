"""Rate-limit responses provide Retry-After guidance."""
from app.security_controls import evaluate_spec

CONTROL = {'id': 'AG-055', 'name': 'retry_after_header', 'field': 'retry_after_on_429', 'operator': 'truthy', 'expected': None, 'severity': 'low', 'description': 'Rate-limit responses provide Retry-After guidance.', 'pass_message': 'Rate-limit responses provide Retry-After guidance.', 'fail_message': 'Rate-limit responses provide Retry-After guidance. Control is not satisfied.'}

def evaluate(observation: dict) -> dict | None:
    """Evaluate Rate-limit responses provide Retry-After guidance."""
    return evaluate_spec(CONTROL, observation)
