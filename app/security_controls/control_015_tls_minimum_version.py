"""TLS 1.2 or newer is negotiated."""
from app.security_controls import evaluate_spec

CONTROL = {'id': 'AG-015', 'name': 'tls_minimum_version', 'field': 'tls_version', 'operator': 'one_of', 'expected': ['TLSv1.2', 'TLSv1.3'], 'severity': 'medium', 'description': 'TLS 1.2 or newer is negotiated.', 'pass_message': 'TLS 1.2 or newer is negotiated.', 'fail_message': 'TLS 1.2 or newer is negotiated. Control is not satisfied.'}

def evaluate(observation: dict) -> dict | None:
    """Evaluate TLS 1.2 or newer is negotiated."""
    return evaluate_spec(CONTROL, observation)
