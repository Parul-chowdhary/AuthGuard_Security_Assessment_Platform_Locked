"""
AuthGuard Risk Scoring Engine
=============================
Calculates standardized CVSS v3.1 scores, OWASP Risk Ratings, and severity levels.
"""

from typing import Tuple


def calculate_cvss_score(
    attack_vector: str = "N",        # Network (0.85)
    attack_complexity: str = "L",    # Low (0.77)
    privileges_required: str = "N",  # None (0.85)
    user_interaction: str = "N",     # None (0.85)
    scope: str = "U",                # Unchanged (6.42 base mult)
    confidentiality: str = "H",      # High (0.56)
    integrity: str = "H",            # High (0.56)
    availability: str = "N",         # None (0.0)
) -> Tuple[float, str]:
    """
    Computes an estimated CVSS v3.1 Base Score and determines Severity tier:
    Critical, High, Medium, Low, Informational.
    """
    # Exploitability sub-score
    av_val = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}.get(attack_vector, 0.85)
    ac_val = {"L": 0.77, "H": 0.44}.get(attack_complexity, 0.77)
    pr_val = {"N": 0.85, "L": 0.62, "H": 0.27}.get(privileges_required, 0.85)
    ui_val = {"N": 0.85, "R": 0.62}.get(user_interaction, 0.85)

    exploitability = 8.22 * av_val * ac_val * pr_val * ui_val

    # Impact sub-score
    c_val = {"H": 0.56, "L": 0.22, "N": 0.0}.get(confidentiality, 0.56)
    i_val = {"H": 0.56, "L": 0.22, "N": 0.0}.get(integrity, 0.56)
    a_val = {"H": 0.56, "L": 0.22, "N": 0.0}.get(availability, 0.0)

    iss = 1.0 - ((1.0 - c_val) * (1.0 - i_val) * (1.0 - a_val))
    impact = 6.42 * iss if scope == "U" else 7.52 * (iss - 0.029) - 3.25 * ((iss - 0.02) ** 15)

    if impact <= 0:
        base_score = 0.0
    else:
        raw_score = min(10.0, impact + exploitability)
        # Round up to 1 decimal place (CVSS v3.1 ceiling rule)
        base_score = round(raw_score, 1)

    if base_score >= 9.0:
        severity = "Critical"
    elif base_score >= 7.0:
        severity = "High"
    elif base_score >= 4.0:
        severity = "Medium"
    elif base_score > 0.0:
        severity = "Low"
    else:
        severity = "Informational"

    return base_score, severity
