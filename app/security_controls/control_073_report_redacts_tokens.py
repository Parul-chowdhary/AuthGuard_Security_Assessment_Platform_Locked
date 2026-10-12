"""Reports redact secrets and bearer tokens."""
from app.security_controls import evaluate_spec

CONTROL = {'id': 'AG-073', 'name': 'report_redacts_tokens', 'field': 'report_token_redaction', 'operator': 'truthy', 'expected': None, 'severity': 'high', 'description': 'Reports redact secrets and bearer tokens.', 'pass_message': 'Reports redact secrets and bearer tokens.', 'fail_message': 'Reports redact secrets and bearer tokens. Control is not satisfied.'}

def evaluate(observation: dict) -> dict | None:
    """Evaluate Reports redact secrets and bearer tokens."""
    return evaluate_spec(CONTROL, observation)
