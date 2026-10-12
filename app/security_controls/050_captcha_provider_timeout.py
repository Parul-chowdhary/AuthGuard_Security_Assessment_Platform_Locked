"""CAPTCHA provider calls have a timeout."""
from app.security_controls import evaluate_spec

CONTROL = {'id': 'AG-050', 'name': 'captcha_provider_timeout', 'field': 'captcha_provider_timeout_seconds', 'operator': 'at_least', 'expected': 1, 'severity': 'low', 'description': 'CAPTCHA provider calls have a timeout.', 'pass_message': 'CAPTCHA provider calls have a timeout.', 'fail_message': 'CAPTCHA provider calls have a timeout. Control is not satisfied.'}

def evaluate(observation: dict) -> dict | None:
    """Evaluate CAPTCHA provider calls have a timeout."""
    return evaluate_spec(CONTROL, observation)
