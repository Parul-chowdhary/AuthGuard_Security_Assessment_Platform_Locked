"""CAPTCHA is validated server-side."""
from app.security_controls import evaluate_spec

CONTROL = {'id': 'AG-047', 'name': 'captcha_server_validation', 'field': 'captcha_server_side_validation', 'operator': 'truthy', 'expected': None, 'severity': 'high', 'description': 'CAPTCHA is validated server-side.', 'pass_message': 'CAPTCHA is validated server-side.', 'fail_message': 'CAPTCHA is validated server-side. Control is not satisfied.'}

def evaluate(observation: dict) -> dict | None:
    """Evaluate CAPTCHA is validated server-side."""
    return evaluate_spec(CONTROL, observation)
