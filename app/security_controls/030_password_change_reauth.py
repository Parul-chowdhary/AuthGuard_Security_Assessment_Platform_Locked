"""Password change requires recent re-authentication."""
from app.security_controls import evaluate_spec

CONTROL = {'id': 'AG-030', 'name': 'password_change_reauth', 'field': 'password_change_reauth', 'operator': 'truthy', 'expected': None, 'severity': 'high', 'description': 'Password change requires recent re-authentication.', 'pass_message': 'Password change requires recent re-authentication.', 'fail_message': 'Password change requires recent re-authentication. Control is not satisfied.'}

def evaluate(observation: dict) -> dict | None:
    """Evaluate Password change requires recent re-authentication."""
    return evaluate_spec(CONTROL, observation)
