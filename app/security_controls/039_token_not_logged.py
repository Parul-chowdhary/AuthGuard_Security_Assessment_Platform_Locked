"""Authentication tokens are excluded from logs."""
from app.security_controls import evaluate_spec

CONTROL = {'id': 'AG-039', 'name': 'token_not_logged', 'field': 'token_logging_disabled', 'operator': 'truthy', 'expected': None, 'severity': 'high', 'description': 'Authentication tokens are excluded from logs.', 'pass_message': 'Authentication tokens are excluded from logs.', 'fail_message': 'Authentication tokens are excluded from logs. Control is not satisfied.'}

def evaluate(observation: dict) -> dict | None:
    """Evaluate Authentication tokens are excluded from logs."""
    return evaluate_spec(CONTROL, observation)
