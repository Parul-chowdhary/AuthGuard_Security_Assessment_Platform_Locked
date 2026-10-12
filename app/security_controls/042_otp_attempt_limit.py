"""OTP verification attempts are bounded."""
from app.security_controls import evaluate_spec

CONTROL = {'id': 'AG-042', 'name': 'otp_attempt_limit', 'field': 'otp_attempt_limit', 'operator': 'at_least', 'expected': 1, 'severity': 'high', 'description': 'OTP verification attempts are bounded.', 'pass_message': 'OTP verification attempts are bounded.', 'fail_message': 'OTP verification attempts are bounded. Control is not satisfied.'}

def evaluate(observation: dict) -> dict | None:
    """Evaluate OTP verification attempts are bounded."""
    return evaluate_spec(CONTROL, observation)
