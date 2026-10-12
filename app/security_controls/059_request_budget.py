"""Assessment requests have an explicit budget."""
from app.security_controls import evaluate_spec

CONTROL = {'id': 'AG-059', 'name': 'request_budget', 'field': 'request_budget_configured', 'operator': 'truthy', 'expected': None, 'severity': 'high', 'description': 'Assessment requests have an explicit budget.', 'pass_message': 'Assessment requests have an explicit budget.', 'fail_message': 'Assessment requests have an explicit budget. Control is not satisfied.'}

def evaluate(observation: dict) -> dict | None:
    """Evaluate Assessment requests have an explicit budget."""
    return evaluate_spec(CONTROL, observation)
