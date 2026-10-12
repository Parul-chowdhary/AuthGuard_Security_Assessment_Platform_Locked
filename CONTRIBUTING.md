# Contributing

1. Create a focused feature branch from `master`.
2. Keep changes small and tie them to a control or bug.
3. Add a regression test; unit tests must use synthetic observations or the local demo lab.
4. Run `python -m pytest -q` and formatting/lint checks where installed.
5. Complete `contribution/PULL_REQUEST_TEMPLATE.md`.
6. Open a real pull request against the hosting repository and request review before merging.

Do not run OTP brute-force, CAPTCHA-bypass, or credential-guessing tests against third-party services. Use the local demo lab or a target for which written authorization exists.
