"""Redirect destinations are revalidated before following."""
from app.security_controls import evaluate_spec

CONTROL = {'id': 'AG-061', 'name': 'redirect_revalidation', 'field': 'redirects_revalidated', 'operator': 'truthy', 'expected': None, 'severity': 'high', 'description': 'Redirect destinations are revalidated before following.', 'pass_message': 'Redirect destinations are revalidated before following.', 'fail_message': 'Redirect destinations are revalidated before following. Control is not satisfied.'}

def evaluate(observation: dict) -> dict | None:
    """Evaluate Redirect destinations are revalidated before following."""
    return evaluate_spec(CONTROL, observation)
