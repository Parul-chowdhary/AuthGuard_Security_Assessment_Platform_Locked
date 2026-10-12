"""State-changing browser requests enforce CSRF protection."""
from app.security_controls import evaluate_spec

CONTROL = {'id': 'AG-035', 'name': 'csrf_protection', 'field': 'csrf_protection', 'operator': 'truthy', 'expected': None, 'severity': 'high', 'description': 'State-changing browser requests enforce CSRF protection.', 'pass_message': 'State-changing browser requests enforce CSRF protection.', 'fail_message': 'State-changing browser requests enforce CSRF protection. Control is not satisfied.'}

def evaluate(observation: dict) -> dict | None:
    """Evaluate State-changing browser requests enforce CSRF protection."""
    return evaluate_spec(CONTROL, observation)
