"""Machine-readable reports include a schema version."""
from app.security_controls import evaluate_spec

CONTROL = {'id': 'AG-077', 'name': 'report_schema_version', 'field': 'report_schema_version', 'operator': 'present', 'expected': None, 'severity': 'low', 'description': 'Machine-readable reports include a schema version.', 'pass_message': 'Machine-readable reports include a schema version.', 'fail_message': 'Machine-readable reports include a schema version. Control is not satisfied.'}

def evaluate(observation: dict) -> dict | None:
    """Evaluate Machine-readable reports include a schema version."""
    return evaluate_spec(CONTROL, observation)
