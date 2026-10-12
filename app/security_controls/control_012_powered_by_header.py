"""Technology disclosure header is absent."""
from app.security_controls import evaluate_spec

CONTROL = {'id': 'AG-012', 'name': 'powered_by_header', 'field': 'x_powered_by', 'operator': 'falsy', 'expected': None, 'severity': 'medium', 'description': 'Technology disclosure header is absent.', 'pass_message': 'Technology disclosure header is absent.', 'fail_message': 'Technology disclosure header is absent. Control is not satisfied.'}

def evaluate(observation: dict) -> dict | None:
    """Evaluate Technology disclosure header is absent."""
    return evaluate_spec(CONTROL, observation)
