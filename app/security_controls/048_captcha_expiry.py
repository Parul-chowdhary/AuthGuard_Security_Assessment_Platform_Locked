"""Expired CAPTCHA tokens are rejected."""
from app.security_controls import evaluate_spec

CONTROL = {'id': 'AG-048', 'name': 'captcha_expiry', 'field': 'captcha_expiry_enforced', 'operator': 'truthy', 'expected': None, 'severity': 'medium', 'description': 'Expired CAPTCHA tokens are rejected.', 'pass_message': 'Expired CAPTCHA tokens are rejected.', 'fail_message': 'Expired CAPTCHA tokens are rejected. Control is not satisfied.'}

def evaluate(observation: dict) -> dict | None:
    """Evaluate Expired CAPTCHA tokens are rejected."""
    return evaluate_spec(CONTROL, observation)
