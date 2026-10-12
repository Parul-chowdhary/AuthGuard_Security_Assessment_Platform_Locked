"""OTP attempts have a finite rate limit."""
from app.security_controls import evaluate_spec

CONTROL = {'id': 'AG-053', 'name': 'otp_rate_limit', 'field': 'otp_rate_limit_per_minute', 'operator': 'at_least', 'expected': 1, 'severity': 'high', 'description': 'OTP attempts have a finite rate limit.', 'pass_message': 'OTP attempts have a finite rate limit.', 'fail_message': 'OTP attempts have a finite rate limit. Control is not satisfied.'}

def evaluate(observation: dict) -> dict | None:
    """Evaluate OTP attempts have a finite rate limit."""
    return evaluate_spec(CONTROL, observation)
