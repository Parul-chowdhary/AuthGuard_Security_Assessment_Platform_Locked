"""Repeated target failures trip a circuit breaker."""
from app.security_controls import evaluate_spec

CONTROL = {'id': 'AG-058', 'name': 'circuit_breaker', 'field': 'circuit_breaker_enabled', 'operator': 'truthy', 'expected': None, 'severity': 'medium', 'description': 'Repeated target failures trip a circuit breaker.', 'pass_message': 'Repeated target failures trip a circuit breaker.', 'fail_message': 'Repeated target failures trip a circuit breaker. Control is not satisfied.'}

def evaluate(observation: dict) -> dict | None:
    """Evaluate Repeated target failures trip a circuit breaker."""
    return evaluate_spec(CONTROL, observation)
