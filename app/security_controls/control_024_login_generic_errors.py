"""Login failures avoid account enumeration."""
from app.security_controls import evaluate_spec

CONTROL = {'id': 'AG-024', 'name': 'login_generic_errors', 'field': 'login_generic_errors', 'operator': 'truthy', 'expected': None, 'severity': 'medium', 'description': 'Login failures avoid account enumeration.', 'pass_message': 'Login failures avoid account enumeration.', 'fail_message': 'Login failures avoid account enumeration. Control is not satisfied.'}

def evaluate(observation: dict) -> dict | None:
    """Evaluate Login failures avoid account enumeration."""
    return evaluate_spec(CONTROL, observation)
