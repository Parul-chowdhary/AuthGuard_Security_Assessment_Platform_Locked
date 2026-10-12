"""OTP cannot be reused."""
from app.security_controls import evaluate_spec

CONTROL = {'id': 'AG-041', 'name': 'otp_single_use', 'field': 'otp_single_use', 'operator': 'truthy', 'expected': None, 'severity': 'high', 'description': 'OTP cannot be reused.', 'pass_message': 'OTP cannot be reused.', 'fail_message': 'OTP cannot be reused. Control is not satisfied.'}

def evaluate(observation: dict) -> dict | None:
    """Evaluate OTP cannot be reused."""
    return evaluate_spec(CONTROL, observation)
