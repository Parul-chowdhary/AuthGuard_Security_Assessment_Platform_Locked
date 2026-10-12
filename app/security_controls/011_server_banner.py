"""Server banner disclosure is absent."""
from app.security_controls import evaluate_spec

CONTROL = {'id': 'AG-011', 'name': 'server_banner', 'field': 'server_banner', 'operator': 'falsy', 'expected': None, 'severity': 'medium', 'description': 'Server banner disclosure is absent.', 'pass_message': 'Server banner disclosure is absent.', 'fail_message': 'Server banner disclosure is absent. Control is not satisfied.'}

def evaluate(observation: dict) -> dict | None:
    """Evaluate Server banner disclosure is absent."""
    return evaluate_spec(CONTROL, observation)
