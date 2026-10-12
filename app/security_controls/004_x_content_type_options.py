"""MIME sniffing is disabled."""
from app.security_controls import evaluate_spec

CONTROL = {'id': 'AG-004', 'name': 'x_content_type_options', 'field': 'x_content_type_options', 'operator': 'equals', 'expected': 'nosniff', 'severity': 'medium', 'description': 'MIME sniffing is disabled.', 'pass_message': 'MIME sniffing is disabled.', 'fail_message': 'MIME sniffing is disabled. Control is not satisfied.'}

def evaluate(observation: dict) -> dict | None:
    """Evaluate MIME sniffing is disabled."""
    return evaluate_spec(CONTROL, observation)
