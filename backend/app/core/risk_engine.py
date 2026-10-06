"""
NetSentinel AI — Risk Calculation & Security Scoring Engine
"""

from typing import Any, Dict, List

# ============================================================
# RISK WEIGHTS
# ============================================================

RISK_WEIGHTS = {
    "CRITICAL": 10,
    "HIGH": 7,
    "MEDIUM": 4,
    "LOW": 1,
    "INFO": 0,
}


# ============================================================
# RISK ENGINE
# ============================================================

def calculate_risk(findings: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Calculate comprehensive risk score, risk level, and failed finding counts.
    """
    risk_points = 0

    severity_counts = {
        "CRITICAL": 0,
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0,
    }

    failed_findings = []

    for finding in findings:
        if finding.get("status") != "FAIL":
            continue

        severity = str(finding.get("severity", "MEDIUM")).upper()

        if severity not in RISK_WEIGHTS:
            severity = "MEDIUM"

        risk_points += RISK_WEIGHTS[severity]
        if severity in severity_counts:
            severity_counts[severity] += 1
        failed_findings.append(finding)

    if severity_counts["CRITICAL"] > 0:
        risk_level = "CRITICAL"
    elif severity_counts["HIGH"] >= 1:
        risk_level = "HIGH"
    elif severity_counts["MEDIUM"] >= 1:
        risk_level = "MEDIUM"
    elif severity_counts["LOW"] > 0:
        risk_level = "LOW"
    else:
        risk_level = "MINIMAL"

    risk_score = 0 if risk_points == 0 else min(100, risk_points * 5)

    return {
        "risk_score": risk_score,
        "risk_level": risk_level,
        "risk_points": risk_points,
        "severity_counts": severity_counts,
        "failed_controls": len(failed_findings),
    }


# ============================================================
# SECURITY SCORE
# ============================================================

def calculate_security_score(findings: List[Dict[str, Any]]) -> int:
    """
    Calculate severity-weighted security compliance score from 0 to 100.
    """
    if not findings:
        return 0

    weighted_total = 0
    weighted_pass = 0

    for finding in findings:
        severity = str(finding.get("severity", "MEDIUM")).upper()
        weight = RISK_WEIGHTS.get(severity, 4)

        if weight == 0:
            weight = 1

        weighted_total += weight

        if finding.get("status") == "PASS":
            weighted_pass += weight

    if weighted_total == 0:
        return 0

    return round((weighted_pass / weighted_total) * 100)
