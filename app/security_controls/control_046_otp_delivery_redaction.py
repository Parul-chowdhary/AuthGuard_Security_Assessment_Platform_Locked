"""OTP values are redacted from delivery logs."""
from app.security_controls import evaluate_spec

CONTROL = {'id': 'AG-046', 'name': 'otp_delivery_redaction', 'field': 'otp_delivery_redacted_in_logs', 'operator': 'truthy', 'expected': None, 'severity': 'high', 'description': 'OTP values are redacted from delivery logs.', 'pass_message': 'OTP values are redacted from delivery logs.', 'fail_message': 'OTP values are redacted from delivery logs. Control is not satisfied.'}

def evaluate(observation: dict) -> dict | None:
    """Evaluate OTP values are redacted from delivery logs."""
    return evaluate_spec(CONTROL, observation)
