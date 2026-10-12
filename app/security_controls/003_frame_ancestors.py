"""CSP frame-ancestors blocks framing."""
from app.security_controls import evaluate_spec

CONTROL = {'id': 'AG-003', 'name': 'frame_ancestors', 'field': 'frame_ancestors', 'operator': 'contains', 'expected': "'none'", 'severity': 'medium', 'description': 'CSP frame-ancestors blocks framing.', 'pass_message': 'CSP frame-ancestors blocks framing.', 'fail_message': 'CSP frame-ancestors blocks framing. Control is not satisfied.'}

def evaluate(observation: dict) -> dict | None:
    """Evaluate CSP frame-ancestors blocks framing."""
    return evaluate_spec(CONTROL, observation)
