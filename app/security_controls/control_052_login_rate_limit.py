"""Login attempts have a finite rate limit."""
from app.security_controls import evaluate_spec

CONTROL = {'id': 'AG-052', 'name': 'login_rate_limit', 'field': 'login_rate_limit_per_minute', 'operator': 'at_least', 'expected': 1, 'severity': 'high', 'description': 'Login attempts have a finite rate limit.', 'pass_message': 'Login attempts have a finite rate limit.', 'fail_message': 'Login attempts have a finite rate limit. Control is not satisfied.'}

def evaluate(observation: dict) -> dict | None:
    """Evaluate Login attempts have a finite rate limit."""
    return evaluate_spec(CONTROL, observation)
