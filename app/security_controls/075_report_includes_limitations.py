"""Reports distinguish observed evidence from limitations."""
from app.security_controls import evaluate_spec

CONTROL = {'id': 'AG-075', 'name': 'report_includes_limitations', 'field': 'report_limitations_included', 'operator': 'truthy', 'expected': None, 'severity': 'low', 'description': 'Reports distinguish observed evidence from limitations.', 'pass_message': 'Reports distinguish observed evidence from limitations.', 'fail_message': 'Reports distinguish observed evidence from limitations. Control is not satisfied.'}

def evaluate(observation: dict) -> dict | None:
    """Evaluate Reports distinguish observed evidence from limitations."""
    return evaluate_spec(CONTROL, observation)
