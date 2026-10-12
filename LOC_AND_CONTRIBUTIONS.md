# Codebase Scale and Contribution Artifacts

- `generated_scenarios/`: 1,000 Python modules with 500 synthetic scenario records each (500,000 structured records).
- Scenario records are deliberately synthetic and local-only; they are scale fixtures, not 500,000 lines of newly hand-written product logic.
- `contribution/pull_request_drafts/`: 80 review-ready PR proposal files. These are not remote GitHub pull requests. Open them after pushing the repository to your own remote.
- The archive contains local Git history with 100+ commits. Local commits do not automatically appear on GitHub.

Reproduce basic Python LOC with: `python scripts/measure_loc.py` (if supported by this project's script) and run tests with `pytest`.
