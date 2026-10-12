"""Assessment concurrency is bounded."""
from app.security_controls import evaluate_spec

CONTROL = {'id': 'AG-064', 'name': 'assessment_concurrency', 'field': 'assessment_concurrency_limit', 'operator': 'at_least', 'expected': 1, 'severity': 'medium', 'description': 'Assessment concurrency is bounded.', 'pass_message': 'Assessment concurrency is bounded.', 'fail_message': 'Assessment concurrency is bounded. Control is not satisfied.'}

def evaluate(observation: dict) -> dict | None:
    """Evaluate Assessment concurrency is bounded."""
    return evaluate_spec(CONTROL, observation)
