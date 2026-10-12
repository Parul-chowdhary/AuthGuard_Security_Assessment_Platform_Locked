## Summary
Describe the user-visible or security-relevant behavior changed.

## Why
Explain the threat model or bug addressed.

## Scope and authorization
Confirm this change only assesses systems explicitly authorized by the operator and does not bypass access controls.

## Tests
- [ ] Unit tests added or updated
- [ ] Regression test demonstrates the previous failure
- [ ] `python -m pytest -q` passes

## Evidence and safety
- [ ] Secrets and tokens are redacted
- [ ] Request budget, timeout, and scope guards remain enforced
- [ ] No live target is contacted by unit tests
