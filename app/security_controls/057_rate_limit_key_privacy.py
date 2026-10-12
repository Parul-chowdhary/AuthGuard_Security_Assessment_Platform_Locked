"""Rate-limit identifiers avoid storing raw personal data."""
from app.security_controls import evaluate_spec

CONTROL = {'id': 'AG-057', 'name': 'rate_limit_key_privacy', 'field': 'rate_limit_key_hashed', 'operator': 'truthy', 'expected': None, 'severity': 'low', 'description': 'Rate-limit identifiers avoid storing raw personal data.', 'pass_message': 'Rate-limit identifiers avoid storing raw personal data.', 'fail_message': 'Rate-limit identifiers avoid storing raw personal data. Control is not satisfied.'}

def evaluate(observation: dict) -> dict | None:
    """Evaluate Rate-limit identifiers avoid storing raw personal data."""
    return evaluate_spec(CONTROL, observation)
