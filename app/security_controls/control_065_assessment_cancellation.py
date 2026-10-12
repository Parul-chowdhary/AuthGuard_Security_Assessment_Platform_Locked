"""An operator can cancel a running assessment."""
from app.security_controls import evaluate_spec

CONTROL = {'id': 'AG-065', 'name': 'assessment_cancellation', 'field': 'assessment_cancellation_supported', 'operator': 'truthy', 'expected': None, 'severity': 'medium', 'description': 'An operator can cancel a running assessment.', 'pass_message': 'An operator can cancel a running assessment.', 'fail_message': 'An operator can cancel a running assessment. Control is not satisfied.'}

def evaluate(observation: dict) -> dict | None:
    """Evaluate An operator can cancel a running assessment."""
    return evaluate_spec(CONTROL, observation)
