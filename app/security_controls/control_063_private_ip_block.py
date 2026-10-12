"""Private and metadata IP ranges are blocked outside the lab."""
from app.security_controls import evaluate_spec

CONTROL = {'id': 'AG-063', 'name': 'private_ip_block', 'field': 'private_ip_blocking', 'operator': 'truthy', 'expected': None, 'severity': 'high', 'description': 'Private and metadata IP ranges are blocked outside the lab.', 'pass_message': 'Private and metadata IP ranges are blocked outside the lab.', 'fail_message': 'Private and metadata IP ranges are blocked outside the lab. Control is not satisfied.'}

def evaluate(observation: dict) -> dict | None:
    """Evaluate Private and metadata IP ranges are blocked outside the lab."""
    return evaluate_spec(CONTROL, observation)
