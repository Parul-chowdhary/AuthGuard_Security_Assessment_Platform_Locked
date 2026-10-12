"""Origin/Referer validation is enabled where applicable."""
from app.security_controls import evaluate_spec

CONTROL = {'id': 'AG-036', 'name': 'origin_check', 'field': 'origin_check_enabled', 'operator': 'truthy', 'expected': None, 'severity': 'medium', 'description': 'Origin/Referer validation is enabled where applicable.', 'pass_message': 'Origin/Referer validation is enabled where applicable.', 'fail_message': 'Origin/Referer validation is enabled where applicable. Control is not satisfied.'}

def evaluate(observation: dict) -> dict | None:
    """Evaluate Origin/Referer validation is enabled where applicable."""
    return evaluate_spec(CONTROL, observation)
