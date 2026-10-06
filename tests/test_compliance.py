"""
Unit tests for NetSentinel AI Compliance Evaluation Engine
"""

import pytest
from backend.app.core.compliance_engine import (
    evaluate_framework,
    build_complete_analysis,
    build_cross_framework_summary,
)


def test_evaluate_secure_cisco_against_cis(cisco_config):
    analysis = build_complete_analysis("secure_cisco.txt", cisco_config, "CIS")

    assert analysis["vendor"] == "Cisco"
    assert analysis["framework"] == "CIS"
    assert analysis["security_score"] >= 80
    assert analysis["compliance_summary"]["overall_status"] in ["COMPLIANT", "PARTIALLY COMPLIANT"]
    assert len(analysis["findings"]) == 7


def test_evaluate_insecure_cisco_against_cis(insecure_cisco_config):
    analysis = build_complete_analysis("insecure_cisco.txt", insecure_cisco_config, "CIS")

    assert analysis["vendor"] == "Cisco"
    assert analysis["framework"] == "CIS"
    assert analysis["security_score"] <= 30
    assert analysis["risk_analysis"]["risk_level"] in ["CRITICAL", "HIGH"]
    assert analysis["failed"] >= 4


def test_cross_framework_evaluation(cisco_config):
    analysis = build_complete_analysis("cisco.txt", cisco_config, "CIS")
    cross = analysis["cross_framework_summary"]

    assert "CIS" in cross["frameworks_evaluated"]
    assert "NIST" in cross["frameworks_evaluated"]
    assert "STIG" in cross["frameworks_evaluated"]
    assert "ISO" in cross["frameworks_evaluated"]
    assert cross["framework_count"] == 4
    assert isinstance(cross["overall_security_score"], int)
