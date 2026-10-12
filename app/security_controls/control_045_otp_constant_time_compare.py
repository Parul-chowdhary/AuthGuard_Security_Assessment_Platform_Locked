"""OTP comparison uses constant-time semantics where applicable."""
from app.security_controls import evaluate_spec

CONTROL = {'id': 'AG-045', 'name': 'otp_constant_time_compare', 'field': 'otp_constant_time_compare', 'operator': 'truthy', 'expected': None, 'severity': 'medium', 'description': 'OTP comparison uses constant-time semantics where applicable.', 'pass_message': 'OTP comparison uses constant-time semantics where applicable.', 'fail_message': 'OTP comparison uses constant-time semantics where applicable. Control is not satisfied.'}

def evaluate(observation: dict) -> dict | None:
    """Evaluate OTP comparison uses constant-time semantics where applicable."""
    return evaluate_spec(CONTROL, observation)
