"""Known-compromised passwords are rejected."""
from app.security_controls import evaluate_spec

CONTROL = {'id': 'AG-029', 'name': 'password_breach_check', 'field': 'password_breach_check', 'operator': 'truthy', 'expected': None, 'severity': 'medium', 'description': 'Known-compromised passwords are rejected.', 'pass_message': 'Known-compromised passwords are rejected.', 'fail_message': 'Known-compromised passwords are rejected. Control is not satisfied.'}

def evaluate(observation: dict) -> dict | None:
    """Evaluate Known-compromised passwords are rejected."""
    return evaluate_spec(CONTROL, observation)
