"""MFA recovery attempts are rate-limited."""
from app.security_controls import evaluate_spec

CONTROL = {'id': 'AG-027', 'name': 'mfa_recovery_rate_limited', 'field': 'mfa_recovery_rate_limited', 'operator': 'truthy', 'expected': None, 'severity': 'high', 'description': 'MFA recovery attempts are rate-limited.', 'pass_message': 'MFA recovery attempts are rate-limited.', 'fail_message': 'MFA recovery attempts are rate-limited. Control is not satisfied.'}

def evaluate(observation: dict) -> dict | None:
    """Evaluate MFA recovery attempts are rate-limited."""
    return evaluate_spec(CONTROL, observation)
