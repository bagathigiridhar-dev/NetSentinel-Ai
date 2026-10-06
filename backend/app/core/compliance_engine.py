"""
NetSentinel AI — Compliance Evaluation Engine & Summary Builder
"""

from typing import Any, Dict, List, Optional
from backend.app.rules.compliance_rules import COMPLIANCE_RULES
from backend.app.rules.learned_rules import load_learned_mappings
from backend.app.core.vendor_detector import detect_vendor
from backend.app.core.normalizer import extract_device_metadata, normalize_configuration
from backend.app.core.risk_engine import RISK_WEIGHTS, calculate_risk, calculate_security_score


# ============================================================
# CONTROL EVALUATION
# ============================================================

def evaluate_normalized_control(rule: Dict[str, Any], normalized: Dict[str, Any]) -> Optional[str]:
    """Evaluate a single rule against normalized security parameters."""
    parameters = normalized.get("security_parameters", {})
    parameter = rule.get("parameter")
    expected = rule.get("expected_value")

    if parameter in parameters:
        actual = parameters[parameter]
        return "PASS" if actual == expected else "FAIL"

    return None


def evaluate_framework(framework: str, normalized: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Evaluate a specific framework against normalized configuration."""
    rules = COMPLIANCE_RULES.get(framework, [])
    findings = []

    for rule in rules:
        status = evaluate_normalized_control(rule, normalized)

        if status is None:
            status = "UNKNOWN"

        findings.append(
            {
                "control_id": rule.get("id"),
                "rule": rule.get("name"),
                "status": status,
                "severity": rule.get("severity"),
                "message": rule.get("description"),
                "remediation": rule.get("remediation"),
                "parameter": rule.get("parameter"),
                "expected_value": rule.get("expected_value"),
            }
        )

    return findings


# ============================================================
# COMPLIANCE SUMMARY
# ============================================================

def build_compliance_summary(
    findings: List[Dict[str, Any]],
    security_score: int,
    risk_analysis: Dict[str, Any],
    unknown_count: int,
) -> Dict[str, Any]:
    """Build high-level compliance summary and prioritize findings."""
    total_controls = len(findings)

    evaluated_controls = sum(
        1 for finding in findings if finding["status"] in ["PASS", "FAIL"]
    )

    passed_controls = sum(
        1 for finding in findings if finding["status"] == "PASS"
    )

    failed_controls = sum(
        1 for finding in findings if finding["status"] == "FAIL"
    )

    compliance_percentage = (
        round((passed_controls / evaluated_controls) * 100)
        if evaluated_controls > 0
        else 0
    )

    priority_findings = [
        {
            "control_id": finding.get("control_id"),
            "rule": finding.get("rule"),
            "severity": finding.get("severity"),
            "remediation": finding.get("remediation"),
        }
        for finding in findings
        if finding["status"] == "FAIL"
    ]

    priority_findings.sort(
        key=lambda item: RISK_WEIGHTS.get(
            str(item.get("severity", "MEDIUM")).upper(),
            4,
        ),
        reverse=True,
    )

    if risk_analysis["risk_level"] == "CRITICAL":
        overall_status = "CRITICAL"
    elif risk_analysis["risk_level"] == "HIGH":
        overall_status = "HIGH RISK"
    elif risk_analysis["risk_level"] == "MEDIUM":
        overall_status = "MODERATE RISK"
    elif security_score >= 90:
        overall_status = "COMPLIANT"
    elif security_score >= 70:
        overall_status = "PARTIALLY COMPLIANT"
    else:
        overall_status = "NEEDS ATTENTION"

    return {
        "overall_status": overall_status,
        "security_score": security_score,
        "compliance_percentage": compliance_percentage,
        "total_controls": total_controls,
        "evaluated_controls": evaluated_controls,
        "passed_controls": passed_controls,
        "failed_controls": failed_controls,
        "unknown_controls": unknown_count,
        "risk_level": risk_analysis["risk_level"],
        "risk_score": risk_analysis["risk_score"],
        "priority_findings": priority_findings[:5],
    }


# ============================================================
# FRAMEWORK SUMMARY
# ============================================================

def build_framework_summary(framework: str, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Build summary metrics for a single framework."""
    passed = sum(1 for finding in findings if finding["status"] == "PASS")
    failed = sum(1 for finding in findings if finding["status"] == "FAIL")
    unknown = sum(1 for finding in findings if finding["status"] == "UNKNOWN")

    security_score = calculate_security_score(findings)
    risk_analysis = calculate_risk(findings)

    compliance_summary = build_compliance_summary(
        findings,
        security_score,
        risk_analysis,
        unknown,
    )

    return {
        "framework": framework,
        "security_score": security_score,
        "passed": passed,
        "failed": failed,
        "unknown": unknown,
        "risk_level": risk_analysis["risk_level"],
        "risk_score": risk_analysis["risk_score"],
        "compliance_percentage": compliance_summary["compliance_percentage"],
        "total_controls": len(findings),
    }


# ============================================================
# CROSS-FRAMEWORK SUMMARY
# ============================================================

def build_cross_framework_summary(framework_results: Dict[str, Any]) -> Dict[str, Any]:
    """Build aggregated cross-framework assessment summary."""
    framework_scores = {}

    total_passed = 0
    total_failed = 0
    total_unknown = 0

    for framework, result in framework_results.items():
        summary = result["summary"]

        framework_scores[framework] = {
            "security_score": summary["security_score"],
            "compliance_percentage": summary["compliance_percentage"],
            "passed": summary["passed"],
            "failed": summary["failed"],
            "unknown": summary["unknown"],
            "risk_level": summary["risk_level"],
            "risk_score": summary["risk_score"],
        }

        total_passed += summary["passed"]
        total_failed += summary["failed"]
        total_unknown += summary["unknown"]

    scores = [
        result["summary"]["security_score"]
        for result in framework_results.values()
    ]

    overall_score = round(sum(scores) / len(scores)) if scores else 0

    if any(
        result["summary"]["risk_level"] == "CRITICAL"
        for result in framework_results.values()
    ):
        overall_risk = "CRITICAL"
    elif any(
        result["summary"]["risk_level"] == "HIGH"
        for result in framework_results.values()
    ):
        overall_risk = "HIGH"
    elif any(
        result["summary"]["risk_level"] == "MEDIUM"
        for result in framework_results.values()
    ):
        overall_risk = "MEDIUM"
    elif any(
        result["summary"]["risk_level"] == "LOW"
        for result in framework_results.values()
    ):
        overall_risk = "LOW"
    else:
        overall_risk = "MINIMAL"

    return {
        "frameworks_evaluated": list(framework_results.keys()),
        "framework_count": len(framework_results),
        "overall_security_score": overall_score,
        "overall_risk_level": overall_risk,
        "total_passed": total_passed,
        "total_failed": total_failed,
        "total_unknown": total_unknown,
        "framework_scores": framework_scores,
    }


# ============================================================
# COMPLETE ANALYSIS BUILDER
# ============================================================

def build_complete_analysis(
    filename: str,
    config: str,
    framework: str,
) -> Dict[str, Any]:
    """Orchestrate the full multi-stage compliance analysis pipeline."""
    vendor = detect_vendor(config)
    device_metadata = extract_device_metadata(config, vendor)
    normalized = normalize_configuration(config, vendor)

    framework = framework.upper().strip()
    if framework not in COMPLIANCE_RULES:
        framework = "CIS"

    findings = evaluate_framework(framework, normalized)

    passed = sum(1 for finding in findings if finding["status"] == "PASS")
    failed = sum(1 for finding in findings if finding["status"] == "FAIL")
    unknown = sum(1 for finding in findings if finding["status"] == "UNKNOWN")

    security_score = calculate_security_score(findings)
    risk_analysis = calculate_risk(findings)

    compliance_summary = build_compliance_summary(
        findings,
        security_score,
        risk_analysis,
        unknown,
    )

    framework_results = {}

    for framework_name in COMPLIANCE_RULES.keys():
        framework_findings = evaluate_framework(
            framework_name,
            normalized,
        )

        framework_summary = build_framework_summary(
            framework_name,
            framework_findings,
        )

        framework_results[framework_name] = {
            "summary": framework_summary,
            "findings": framework_findings,
        }

    cross_framework_summary = build_cross_framework_summary(
        framework_results
    )

    learned_mappings = load_learned_mappings()

    learned_used = [
        item
        for item in normalized["recognized_patterns"]
        if item.get("source") == "administrator_training"
    ]

    return {
        "device": filename,
        "device_identification": device_metadata,
        "vendor": vendor,
        "framework": framework,
        "compliance_summary": compliance_summary,
        "cross_framework_summary": cross_framework_summary,
        "framework_results": framework_results,
        "security_score": security_score,
        "risk_analysis": risk_analysis,
        "passed": passed,
        "failed": failed,
        "unknown": unknown,
        "findings": findings,
        "security_baseline_model": {
            "schema_version": normalized["schema_version"],
            "vendor": vendor,
            "parameters": normalized["security_parameters"],
            "controls": normalized["normalized_controls"],
        },
        "normalization": normalized,
        "unknown_configuration_queue": normalized["unknown_objects"],
        "learning": {
            "total_learned": len(learned_mappings),
            "learned_patterns_used": len(learned_used),
            "patterns": learned_used,
        },
    }
