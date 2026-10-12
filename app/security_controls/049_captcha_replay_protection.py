"""CAPTCHA tokens cannot be replayed."""
from app.security_controls import evaluate_spec

CONTROL = {'id': 'AG-049', 'name': 'captcha_replay_protection', 'field': 'captcha_replay_protection', 'operator': 'truthy', 'expected': None, 'severity': 'high', 'description': 'CAPTCHA tokens cannot be replayed.', 'pass_message': 'CAPTCHA tokens cannot be replayed.', 'fail_message': 'CAPTCHA tokens cannot be replayed. Control is not satisfied.'}

def evaluate(observation: dict) -> dict | None:
    """Evaluate CAPTCHA tokens cannot be replayed."""
    return evaluate_spec(CONTROL, observation)
