"""HSTS is present on HTTPS responses."""
from app.security_controls import evaluate_spec

CONTROL = {'id': 'AG-002', 'name': 'strict_transport_security', 'field': 'strict_transport_security', 'operator': 'present', 'expected': None, 'severity': 'medium', 'description': 'HSTS is present on HTTPS responses.', 'pass_message': 'HSTS is present on HTTPS responses.', 'fail_message': 'HSTS is present on HTTPS responses. Control is not satisfied.'}

def evaluate(observation: dict) -> dict | None:
    """Evaluate HSTS is present on HTTPS responses."""
    return evaluate_spec(CONTROL, observation)
