"""
Unit tests for NetSentinel AI Risk Engine & Scoring Calculations
"""

import pytest
from backend.app.core.risk_engine import calculate_risk, calculate_security_score


def test_calculate_risk_empty():
    res = calculate_risk([])
    assert res["risk_level"] == "MINIMAL"
    assert res["risk_score"] == 0
    assert res["risk_points"] == 0
    assert res["failed_controls"] == 0


def test_calculate_risk_critical():
    findings = [
        {"status": "FAIL", "severity": "CRITICAL", "rule": "No Plaintext Password"},
        {"status": "PASS", "severity": "HIGH", "rule": "SSH v2"},
    ]
    res = calculate_risk(findings)
    assert res["risk_level"] == "CRITICAL"
    assert res["severity_counts"]["CRITICAL"] == 1
    assert res["risk_points"] == 10
    assert res["risk_score"] == 50


def test_calculate_security_score():
    findings = [
        {"status": "PASS", "severity": "HIGH"},
        {"status": "PASS", "severity": "HIGH"},
        {"status": "FAIL", "severity": "HIGH"},
    ]
    # 2 pass (weight 7*2 = 14), 1 fail (weight 7), total = 21 -> 14/21 = 67%
    score = calculate_security_score(findings)
    assert score == 67
