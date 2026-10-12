"""Password reset requests have a finite rate limit."""
from app.security_controls import evaluate_spec

CONTROL = {'id': 'AG-054', 'name': 'reset_rate_limit', 'field': 'password_reset_rate_limit_per_hour', 'operator': 'at_least', 'expected': 1, 'severity': 'high', 'description': 'Password reset requests have a finite rate limit.', 'pass_message': 'Password reset requests have a finite rate limit.', 'fail_message': 'Password reset requests have a finite rate limit. Control is not satisfied.'}

def evaluate(observation: dict) -> dict | None:
    """Evaluate Password reset requests have a finite rate limit."""
    return evaluate_spec(CONTROL, observation)
