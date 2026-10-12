#!/usr/bin/env python3
"""Generate deterministic synthetic, local-only AuthGuard regression scenarios."""
from pathlib import Path
import json
ROOT = Path(__file__).resolve().parents[1] / "generated_scenarios"
CASES_PER_MODULE = 500
MODULE_COUNT = 1000
CATEGORIES = ("otp_policy", "captcha_policy", "rate_limit_policy", "session_policy", "report_integrity", "scope_enforcement", "redaction", "rbac")
def main():
    ROOT.mkdir(parents=True, exist_ok=True)
    for module in range(MODULE_COUNT):
        rows = []
        for index in range(CASES_PER_MODULE):
            case_id = module * CASES_PER_MODULE + index + 1
            category = CATEGORIES[case_id % len(CATEGORIES)]
            rows.append({"id": f"SYN-{case_id:07d}", "category": category, "environment": "bundled_demo_lab", "network_required": False, "expected": "policy_enforced", "synthetic": True, "tags": ["regression", "safe-lab", category]})
        payload = "# Synthetic test records; no network activity is performed.\nSCENARIOS = " + repr(rows) + "\n"
        (ROOT / f"scenario_{module+1:04d}.py").write_text(payload, encoding="utf-8")
    print(f"Generated {MODULE_COUNT * CASES_PER_MODULE} synthetic local-only scenarios")
if __name__ == "__main__": main()
