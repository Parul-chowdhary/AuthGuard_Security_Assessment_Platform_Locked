"""Registration response avoids account enumeration."""
from app.security_controls import evaluate_spec

CONTROL = {'id': 'AG-025', 'name': 'registration_generic_errors', 'field': 'registration_generic_errors', 'operator': 'truthy', 'expected': None, 'severity': 'low', 'description': 'Registration response avoids account enumeration.', 'pass_message': 'Registration response avoids account enumeration.', 'fail_message': 'Registration response avoids account enumeration. Control is not satisfied.'}

def evaluate(observation: dict) -> dict | None:
    """Evaluate Registration response avoids account enumeration."""
    return evaluate_spec(CONTROL, observation)
