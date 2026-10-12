"""CAPTCHA provider failures fail closed for protected actions."""
from app.security_controls import evaluate_spec

CONTROL = {'id': 'AG-051', 'name': 'captcha_fail_closed', 'field': 'captcha_provider_failure_mode', 'operator': 'equals', 'expected': 'fail_closed', 'severity': 'high', 'description': 'CAPTCHA provider failures fail closed for protected actions.', 'pass_message': 'CAPTCHA provider failures fail closed for protected actions.', 'fail_message': 'CAPTCHA provider failures fail closed for protected actions. Control is not satisfied.'}

def evaluate(observation: dict) -> dict | None:
    """Evaluate CAPTCHA provider failures fail closed for protected actions."""
    return evaluate_spec(CONTROL, observation)
