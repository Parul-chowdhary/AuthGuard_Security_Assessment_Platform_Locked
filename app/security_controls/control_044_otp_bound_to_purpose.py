"""OTP is bound to a specific transaction purpose."""
from app.security_controls import evaluate_spec

CONTROL = {'id': 'AG-044', 'name': 'otp_bound_to_purpose', 'field': 'otp_purpose_bound', 'operator': 'truthy', 'expected': None, 'severity': 'medium', 'description': 'OTP is bound to a specific transaction purpose.', 'pass_message': 'OTP is bound to a specific transaction purpose.', 'fail_message': 'OTP is bound to a specific transaction purpose. Control is not satisfied.'}

def evaluate(observation: dict) -> dict | None:
    """Evaluate OTP is bound to a specific transaction purpose."""
    return evaluate_spec(CONTROL, observation)
