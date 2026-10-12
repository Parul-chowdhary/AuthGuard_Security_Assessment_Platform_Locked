"""OTP is bound to the initiating session."""
from app.security_controls import evaluate_spec

CONTROL = {'id': 'AG-043', 'name': 'otp_bound_to_session', 'field': 'otp_session_bound', 'operator': 'truthy', 'expected': None, 'severity': 'high', 'description': 'OTP is bound to the initiating session.', 'pass_message': 'OTP is bound to the initiating session.', 'fail_message': 'OTP is bound to the initiating session. Control is not satisfied.'}

def evaluate(observation: dict) -> dict | None:
    """Evaluate OTP is bound to the initiating session."""
    return evaluate_spec(CONTROL, observation)
