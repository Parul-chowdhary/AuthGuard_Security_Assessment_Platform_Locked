"""Rate limits are shared across application workers."""
from app.security_controls import evaluate_spec

CONTROL = {'id': 'AG-056', 'name': 'distributed_rate_limit', 'field': 'rate_limit_shared_store', 'operator': 'truthy', 'expected': None, 'severity': 'medium', 'description': 'Rate limits are shared across application workers.', 'pass_message': 'Rate limits are shared across application workers.', 'fail_message': 'Rate limits are shared across application workers. Control is not satisfied.'}

def evaluate(observation: dict) -> dict | None:
    """Evaluate Rate limits are shared across application workers."""
    return evaluate_spec(CONTROL, observation)
