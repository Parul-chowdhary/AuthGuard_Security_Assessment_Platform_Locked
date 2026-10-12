"""OTP lifetime is bounded."""
from app.security_controls import evaluate_spec

CONTROL = {'id': 'AG-040', 'name': 'otp_expiry', 'field': 'otp_ttl_seconds', 'operator': 'at_least', 'expected': 1, 'severity': 'high', 'description': 'OTP lifetime is bounded.', 'pass_message': 'OTP lifetime is bounded.', 'fail_message': 'OTP lifetime is bounded. Control is not satisfied.'}

def evaluate(observation: dict) -> dict | None:
    """Evaluate OTP lifetime is bounded."""
    return evaluate_spec(CONTROL, observation)
