"""Reports state the authorized assessment scope."""
from app.security_controls import evaluate_spec

CONTROL = {'id': 'AG-074', 'name': 'report_includes_scope', 'field': 'report_scope_included', 'operator': 'truthy', 'expected': None, 'severity': 'medium', 'description': 'Reports state the authorized assessment scope.', 'pass_message': 'Reports state the authorized assessment scope.', 'fail_message': 'Reports state the authorized assessment scope. Control is not satisfied.'}

def evaluate(observation: dict) -> dict | None:
    """Evaluate Reports state the authorized assessment scope."""
    return evaluate_spec(CONTROL, observation)
