from fastapi import FastAPI, UploadFile, File, Form
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse

from backend.rules.compliance_rules import COMPLIANCE_RULES
from backend.rules.learned_rules import (
    add_learned_mapping,
    find_matching_learned_mapping,
    load_learned_mappings,
    get_learning_statistics,
)

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
)

import os
from datetime import datetime


# ============================================================
# NETSENTINEL AI
# ============================================================

app = FastAPI(
    title="NetSentinel AI",
    description="AI-powered Vendor-Agnostic Network Security Compliance Engine",
    version="2.3.0",
)


# ============================================================
# CORS
# ============================================================

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ============================================================
# HOME
# ============================================================

@app.get("/")
def home():
    return {
        "application": "NetSentinel AI",
        "status": "online",
        "message": "Cybersecurity Compliance Engine is running!",
    }


# ============================================================
# VENDOR DETECTION
# ============================================================

def detect_vendor(config):
    config_lower = config.lower()

    if (
        "cisco ios" in config_lower
        or "version 15." in config_lower
        or (
            "hostname " in config_lower
            and "interface " in config_lower
            and "line vty" in config_lower
        )
    ):
        return "Cisco"

    if (
        "juniper" in config_lower
        or "set system host-name" in config_lower
        or "set interfaces " in config_lower
    ):
        return "Juniper"

    if (
        "fortigate" in config_lower
        or "config system global" in config_lower
        or "config firewall policy" in config_lower
    ):
        return "Fortinet"

    if (
        "palo alto" in config_lower
        or "pan-os" in config_lower
        or "set deviceconfig" in config_lower
        or "<entry name=" in config_lower
    ):
        return "Palo Alto"

    if "arista" in config_lower or "eos" in config_lower:
        return "Arista"

    if "sonic" in config_lower or "sonic_version" in config_lower:
        return "SONiC"

    return "Unknown"


# ============================================================
# VALUE CONVERSION
# ============================================================

def convert_value(value):
    if isinstance(value, bool):
        return value

    if value is None:
        return value

    value_string = str(value).strip()

    if value_string.lower() == "true":
        return True

    if value_string.lower() == "false":
        return False

    try:
        return int(value_string)
    except ValueError:
        pass

    try:
        return float(value_string)
    except ValueError:
        pass

    return value_string


# ============================================================
# SECURITY PARAMETER
# ============================================================

def create_security_parameter(
    category,
    parameter,
    value,
    vendor,
    source,
    command,
    severity=None,
):
    item = {
        "category": category,
        "parameter": parameter,
        "value": value,
        "vendor": vendor,
        "source": source,
        "command": command,
    }

    if severity:
        item["severity"] = severity

    return item


# ============================================================
# DEVICE METADATA
# ============================================================

def extract_device_metadata(config, vendor):
    metadata = {
        "vendor": vendor,
        "hostname": None,
        "model": None,
        "serial_number": None,
        "software_version": None,
        "hardware_details": {},
    }

    lines = config.splitlines()

    for line in lines:
        clean = line.strip()
        lower = clean.lower()

        if not clean:
            continue

        if lower.startswith("hostname "):
            metadata["hostname"] = clean.split(None, 1)[1].strip()

        elif lower.startswith("system-name "):
            metadata["hostname"] = clean.split(None, 1)[1].strip()

        elif "set system host-name" in lower:
            metadata["hostname"] = clean.split(
                "set system host-name", 1
            )[1].strip()

        if lower.startswith("version "):
            metadata["software_version"] = clean.split(None, 1)[1].strip()

        elif lower.startswith("device-os "):
            metadata["software_version"] = clean.split(None, 1)[1].strip()

        elif lower.startswith("software-version "):
            metadata["software_version"] = clean.split(None, 1)[1].strip()

        if lower.startswith("model "):
            metadata["model"] = clean.split(None, 1)[1].strip()

        elif lower.startswith("device-model "):
            metadata["model"] = clean.split(None, 1)[1].strip()

        if lower.startswith("serial-number "):
            metadata["serial_number"] = clean.split(None, 1)[1].strip()

        elif lower.startswith("serial "):
            metadata["serial_number"] = clean.split(None, 1)[1].strip()

        if lower.startswith("memory "):
            metadata["hardware_details"]["memory"] = clean.split(None, 1)[1].strip()

        if lower.startswith("processor "):
            metadata["hardware_details"]["processor"] = clean.split(None, 1)[1].strip()

        if lower.startswith("interfaces "):
            metadata["hardware_details"]["interfaces"] = clean.split(None, 1)[1].strip()

    return metadata


# ============================================================
# NORMALIZATION ENGINE
# ============================================================

def normalize_configuration(config, vendor):
    normalized = {
        "schema_version": "1.0",
        "vendor": vendor,
        "security_parameters": {},
        "normalized_controls": [],
        "recognized_patterns": [],
        "unknown_lines": [],
        "unknown_objects": [],
    }

    config_lower = config.lower()

    def add_parameter(
        category,
        parameter,
        value,
        source,
        command,
        severity=None,
    ):
        value = convert_value(value)

        normalized["security_parameters"][parameter] = value

        normalized["normalized_controls"].append(
            create_security_parameter(
                category,
                parameter,
                value,
                vendor,
                source,
                command,
                severity,
            )
        )

        normalized["recognized_patterns"].append(
            {
                "parameter": parameter,
                "value": value,
                "category": category,
                "source": source,
                "command": command,
            }
        )

    built_in_patterns = [
        "ip ssh version 2",
        "ip ssh version 1",
        "transport input telnet",
        "transport input ssh",
        "ip http server",
        "no ip http server",
        "ip http secure-server",
        "https enable",
        "https enabled",
        "no logging",
        "logging buffered",
        "logging host",
        "enable password",
        "enable secret",
        "password encryption",
        "service password-encryption",
        "aaa new-model",
        "aaa authentication",
        "aaa authorization",
        "aaa accounting",
        "snmp-server community",
        "snmpv3",
        "snmp v3",
        "ntp server",
        "ntp enable",
        "ntp enabled",
        "access-list",
        "ip access-group",
        "firewall policy",
        "security policy",
        "ipsec",
        "encryption",
        "line vty",
    ]

    # SSH
    if "ip ssh version 2" in config_lower:
        add_parameter(
            "secure_remote_administration",
            "ssh_version",
            2,
            "built_in_rule",
            "ip ssh version 2",
        )
    elif "ip ssh version 1" in config_lower:
        add_parameter(
            "secure_remote_administration",
            "ssh_version",
            1,
            "built_in_rule",
            "ip ssh version 1",
        )

    # TELNET
    if "transport input telnet" in config_lower:
        add_parameter(
            "secure_remote_administration",
            "telnet_enabled",
            True,
            "built_in_rule",
            "transport input telnet",
        )
    elif "transport input ssh" in config_lower:
        add_parameter(
            "secure_remote_administration",
            "telnet_enabled",
            False,
            "built_in_rule",
            "transport input ssh",
        )

    # HTTP
    if (
        "ip http server" in config_lower
        or "http-server enable" in config_lower
    ):
        add_parameter(
            "secure_management",
            "http_enabled",
            True,
            "built_in_rule",
            "HTTP management enabled",
        )

    if (
        "no ip http server" in config_lower
        or "http-server disable" in config_lower
    ):
        add_parameter(
            "secure_management",
            "http_enabled",
            False,
            "built_in_rule",
            "HTTP management disabled",
        )

    # HTTPS
    if (
        "ip http secure-server" in config_lower
        or "https enable" in config_lower
        or "https enabled" in config_lower
    ):
        add_parameter(
            "secure_management",
            "https_enabled",
            True,
            "built_in_rule",
            "HTTPS management enabled",
        )

    # LOGGING
    if "no logging" in config_lower:
        add_parameter(
            "security_monitoring",
            "logging_enabled",
            False,
            "built_in_rule",
            "no logging",
        )

    if "logging buffered" in config_lower:
        add_parameter(
            "security_monitoring",
            "logging_enabled",
            True,
            "built_in_rule",
            "logging buffered",
        )

    if "logging host" in config_lower:
        add_parameter(
            "security_monitoring",
            "remote_logging_enabled",
            True,
            "built_in_rule",
            "logging host",
        )

    # PASSWORD
    if "enable password" in config_lower:
        add_parameter(
            "credential_protection",
            "plaintext_password",
            True,
            "built_in_rule",
            "enable password",
        )

    if "enable secret" in config_lower:
        add_parameter(
            "credential_protection",
            "plaintext_password",
            False,
            "built_in_rule",
            "enable secret",
        )

    if (
        "password encryption" in config_lower
        or "service password-encryption" in config_lower
    ):
        add_parameter(
            "credential_protection",
            "password_encryption_enabled",
            True,
            "built_in_rule",
            "password encryption",
        )

    # AAA
    if (
        "aaa new-model" in config_lower
        or "aaa authentication" in config_lower
        or "aaa authorization" in config_lower
        or "aaa accounting" in config_lower
    ):
        add_parameter(
            "identity_and_access_management",
            "aaa_enabled",
            True,
            "built_in_rule",
            "AAA configuration",
        )

    # SNMP
    if "snmp-server community" in config_lower:
        add_parameter(
            "network_management",
            "snmp_enabled",
            True,
            "built_in_rule",
            "SNMP community",
        )

        add_parameter(
            "network_management",
            "snmp_v1_v2_detected",
            True,
            "built_in_rule",
            "SNMPv1/v2 detected",
        )

    if "snmpv3" in config_lower or "snmp v3" in config_lower:
        add_parameter(
            "network_management",
            "snmp_v3_enabled",
            True,
            "built_in_rule",
            "SNMPv3 detected",
        )

    # NTP
    if (
        "ntp server" in config_lower
        or "ntp enable" in config_lower
        or "ntp enabled" in config_lower
    ):
        add_parameter(
            "time_synchronization",
            "ntp_enabled",
            True,
            "built_in_rule",
            "NTP configuration",
        )

    # ACCESS CONTROL
    if (
        "access-list" in config_lower
        or "ip access-group" in config_lower
        or "firewall policy" in config_lower
        or "security policy" in config_lower
    ):
        add_parameter(
            "access_control",
            "access_control_configured",
            True,
            "built_in_rule",
            "Access control configuration",
        )

    # ENCRYPTION
    if (
        "encryption" in config_lower
        or "aes" in config_lower
        or "ipsec" in config_lower
    ):
        add_parameter(
            "cryptography",
            "encryption_configured",
            True,
            "built_in_rule",
            "Encryption configuration",
        )

    # ADMINISTRATIVE ACCESS
    if (
        "line vty" in config_lower
        or "admin user" in config_lower
        or "administrator" in config_lower
        or "management access" in config_lower
    ):
        add_parameter(
            "administrative_access",
            "administrative_access_configured",
            True,
            "built_in_rule",
            "Administrative access configuration",
        )

    # UNKNOWN + LEARNED
    for line in config.splitlines():
        clean_line = line.strip()

        if not clean_line:
            continue

        line_lower = clean_line.lower()
        recognized = False

        for pattern in built_in_patterns:
            if pattern in line_lower:
                recognized = True
                break

        learned = find_matching_learned_mapping(clean_line)

        if learned:
            recognized = True

            parameter = learned.get("parameter")
            value = convert_value(learned.get("value"))
            category = learned.get("category", "unknown")
            severity = learned.get("severity", "MEDIUM")

            if parameter:
                add_parameter(
                    category,
                    parameter,
                    value,
                    "administrator_training",
                    clean_line,
                    severity,
                )

        if not recognized:
            normalized["unknown_lines"].append(clean_line)

    # UNKNOWN OBJECTS
    for index, line in enumerate(
        normalized["unknown_lines"],
        start=1,
    ):
        normalized["unknown_objects"].append(
            {
                "id": f"UNKNOWN-{index:03d}",
                "command": line,
                "vendor": vendor,
                "status": "unmapped",
                "training_required": True,
            }
        )

    # SUMMARY
    normalized["summary"] = {
        "parameters_detected": len(
            normalized["security_parameters"]
        ),
        "normalized_controls": len(
            normalized["normalized_controls"]
        ),
        "recognized_patterns": len(
            normalized["recognized_patterns"]
        ),
        "unknown_lines": len(
            normalized["unknown_lines"]
        ),
        "training_candidates": len(
            normalized["unknown_objects"]
        ),
    }

    return normalized


# ============================================================
# COMPLIANCE EVALUATION
# ============================================================

def evaluate_normalized_control(rule, normalized):
    parameters = normalized.get("security_parameters", {})
    parameter = rule.get("parameter")
    expected = rule.get("expected_value")

    if parameter in parameters:
        actual = parameters[parameter]
        return "PASS" if actual == expected else "FAIL"

    return None


def evaluate_framework(framework, normalized):
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
# RISK ENGINE
# ============================================================

RISK_WEIGHTS = {
    "CRITICAL": 10,
    "HIGH": 7,
    "MEDIUM": 4,
    "LOW": 1,
    "INFO": 0,
}


def calculate_risk(findings):
    risk_points = 0

    severity_counts = {
        "CRITICAL": 0,
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0,
    }

    failed_findings = []

    for finding in findings:
        if finding["status"] != "FAIL":
            continue

        severity = str(
            finding.get("severity", "MEDIUM")
        ).upper()

        if severity not in RISK_WEIGHTS:
            severity = "MEDIUM"

        risk_points += RISK_WEIGHTS[severity]
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

def calculate_security_score(findings):
    if not findings:
        return 0

    weighted_total = 0
    weighted_pass = 0

    for finding in findings:
        severity = str(
            finding.get("severity", "MEDIUM")
        ).upper()

        weight = RISK_WEIGHTS.get(severity, 4)

        if weight == 0:
            weight = 1

        weighted_total += weight

        if finding["status"] == "PASS":
            weighted_pass += weight

    if weighted_total == 0:
        return 0

    return round(
        (weighted_pass / weighted_total) * 100
    )


# ============================================================
# COMPLIANCE SUMMARY
# ============================================================

def build_compliance_summary(
    findings,
    security_score,
    risk_analysis,
    unknown_count,
):
    total_controls = len(findings)

    evaluated_controls = sum(
        1
        for finding in findings
        if finding["status"] in ["PASS", "FAIL"]
    )

    passed_controls = sum(
        1
        for finding in findings
        if finding["status"] == "PASS"
    )

    failed_controls = sum(
        1
        for finding in findings
        if finding["status"] == "FAIL"
    )

    compliance_percentage = (
        round(
            (passed_controls / evaluated_controls) * 100
        )
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

def build_framework_summary(framework, findings):
    passed = sum(
        1 for finding in findings
        if finding["status"] == "PASS"
    )

    failed = sum(
        1 for finding in findings
        if finding["status"] == "FAIL"
    )

    unknown = sum(
        1 for finding in findings
        if finding["status"] == "UNKNOWN"
    )

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
        "compliance_percentage": compliance_summary[
            "compliance_percentage"
        ],
        "total_controls": len(findings),
    }


# ============================================================
# CROSS-FRAMEWORK SUMMARY
# ============================================================

def build_cross_framework_summary(framework_results):
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

    overall_score = (
        round(sum(scores) / len(scores))
        if scores
        else 0
    )

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
    filename,
    config,
    framework,
):
    vendor = detect_vendor(config)

    device_metadata = extract_device_metadata(
        config,
        vendor,
    )

    normalized = normalize_configuration(
        config,
        vendor,
    )

    framework = framework.upper().strip()

    if framework not in COMPLIANCE_RULES:
        framework = "CIS"

    findings = evaluate_framework(
        framework,
        normalized,
    )

    passed = sum(
        1 for finding in findings
        if finding["status"] == "PASS"
    )

    failed = sum(
        1 for finding in findings
        if finding["status"] == "FAIL"
    )

    unknown = sum(
        1 for finding in findings
        if finding["status"] == "UNKNOWN"
    )

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
        "unknown_configuration_queue": normalized[
            "unknown_objects"
        ],
        "learning": {
            "total_learned": len(learned_mappings),
            "learned_patterns_used": len(learned_used),
            "patterns": learned_used,
        },
    }


# ============================================================
# ANALYZE
# ============================================================

@app.post("/analyze")
async def analyze_config(
    file: UploadFile = File(...),
    framework: str = Form("CIS"),
):
    content = await file.read()

    config = content.decode(
        "utf-8",
        errors="ignore",
    )

    return build_complete_analysis(
        file.filename or "configuration.txt",
        config,
        framework,
    )


# ============================================================
# TRAIN
# ============================================================

@app.post("/train")
async def train_configuration(
    command: str = Form(...),
    category: str = Form(...),
    parameter: str = Form(...),
    value: str = Form(...),
    severity: str = Form("MEDIUM"),
):
    command = command.strip()
    category = category.strip()
    parameter = parameter.strip()
    value = value.strip()
    severity = severity.upper().strip()

    if not command:
        return {
            "success": False,
            "message": "Command is required.",
        }

    if not category:
        return {
            "success": False,
            "message": "Category is required.",
        }

    if not parameter:
        return {
            "success": False,
            "message": "Parameter is required.",
        }

    if not value:
        return {
            "success": False,
            "message": "Value is required.",
        }

    allowed_severities = {
        "CRITICAL",
        "HIGH",
        "MEDIUM",
        "LOW",
        "INFO",
    }

    if severity not in allowed_severities:
        severity = "MEDIUM"

    final_value = convert_value(value)

    mapping = add_learned_mapping(
        command=command,
        category=category,
        parameter=parameter,
        value=final_value,
        severity=severity,
    )

    saved_mappings = load_learned_mappings()

    return {
        "success": True,
        "message": "NetSentinel learned the new configuration pattern.",
        "learning": mapping,
        "total_learned": len(saved_mappings),
    }


# ============================================================
# LEARNED MAPPINGS
# ============================================================

@app.get("/learned")
def get_learned_mappings():
    mappings = load_learned_mappings()

    return {
        "count": len(mappings),
        "mappings": mappings,
    }


# ============================================================
# LEARNING STATISTICS
# ============================================================

@app.get("/learning/stats")
def learning_statistics():
    return get_learning_statistics()


# ============================================================
# SECURITY BASELINE MODEL
# ============================================================

@app.get("/model")
def security_baseline_model():
    return {
        "name": "NetSentinel Security Baseline Model",
        "schema_version": "1.0",
        "description": (
            "Vendor-neutral representation of network security configuration."
        ),
        "categories": [
            "secure_remote_administration",
            "secure_management",
            "security_monitoring",
            "credential_protection",
            "identity_and_access_management",
            "network_management",
            "time_synchronization",
            "access_control",
            "cryptography",
            "insecure_services",
            "administrative_access",
            "audit_logging",
        ],
        "parameters": [
            "ssh_version",
            "ssh_enabled",
            "telnet_enabled",
            "http_enabled",
            "https_enabled",
            "logging_enabled",
            "remote_logging_enabled",
            "plaintext_password",
            "password_encryption_enabled",
            "aaa_enabled",
            "snmp_enabled",
            "snmp_v1_v2_detected",
            "snmp_v3_enabled",
            "ntp_enabled",
            "access_control_configured",
            "encryption_configured",
            "ftp_enabled",
            "tftp_enabled",
            "administrative_access_configured",
        ],
    }


# ============================================================
# HEALTH
# ============================================================

@app.get("/health")
def health_check():
    return {
        "status": "healthy",
        "application": "NetSentinel AI",
        "version": "2.3.0",
        "learned_mappings": len(load_learned_mappings()),
    }


# ============================================================
# PDF REPORT GENERATOR
# ============================================================

def generate_compliance_report(analysis):
    reports_dir = "reports"
    os.makedirs(reports_dir, exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    filename = (
        "NetSentinel_Complete_Report_"
        + timestamp
        + ".pdf"
    )

    report_path = os.path.join(
        reports_dir,
        filename,
    )

    document = SimpleDocTemplate(
        report_path,
        pagesize=A4,
        rightMargin=15 * mm,
        leftMargin=15 * mm,
        topMargin=15 * mm,
        bottomMargin=15 * mm,
    )

    styles = getSampleStyleSheet()

    title_style = ParagraphStyle(
        "NetSentinelTitle",
        parent=styles["Title"],
        fontSize=24,
        leading=28,
        alignment=TA_CENTER,
        spaceAfter=10,
    )

    subtitle_style = ParagraphStyle(
        "NetSentinelSubtitle",
        parent=styles["Normal"],
        fontSize=11,
        alignment=TA_CENTER,
        textColor=colors.grey,
        spaceAfter=20,
    )

    heading_style = ParagraphStyle(
        "SectionHeading",
        parent=styles["Heading2"],
        fontSize=16,
        leading=20,
        spaceBefore=12,
        spaceAfter=10,
    )

    normal_style = ParagraphStyle(
        "NormalReport",
        parent=styles["Normal"],
        fontSize=9,
        leading=13,
    )

    small_style = ParagraphStyle(
        "SmallReport",
        parent=styles["Normal"],
        fontSize=7.5,
        leading=10,
    )

    story = []

    device = analysis.get("device", "Unknown")
    vendor = analysis.get("vendor", "Unknown")
    framework = analysis.get("framework", "CIS")
    device_info = analysis.get("device_identification", {})
    security_score = analysis.get("security_score", 0)
    risk_analysis = analysis.get("risk_analysis", {})
    findings = analysis.get("findings", [])
    unknown_queue = analysis.get(
        "unknown_configuration_queue",
        [],
    )
    cross_framework = analysis.get(
        "cross_framework_summary",
        {},
    )
    compliance_summary = analysis.get(
        "compliance_summary",
        {},
    )

    # ========================================================
    # TITLE
    # ========================================================

    story.append(
        Paragraph(
            "NetSentinel AI",
            title_style,
        )
    )

    story.append(
        Paragraph(
            "Complete Network Security & Compliance Report",
            subtitle_style,
        )
    )

    story.append(
        Paragraph(
            "AI-Powered Vendor-Agnostic Network Security Compliance Engine",
            subtitle_style,
        )
    )

    # ========================================================
    # EXECUTIVE SUMMARY
    # ========================================================

    story.append(
        Paragraph(
            "1. Executive Summary",
            heading_style,
        )
    )

    summary_data = [
        ["Property", "Result"],
        ["Configuration File", str(device)],
        ["Detected Vendor", str(vendor)],
        ["Selected Framework", str(framework)],
        ["Security Score", str(security_score) + "%"],
        [
            "Compliance",
            str(
                compliance_summary.get(
                    "compliance_percentage",
                    0,
                )
            ) + "%",
        ],
        [
            "Overall Status",
            str(
                compliance_summary.get(
                    "overall_status",
                    "N/A",
                )
            ),
        ],
        [
            "Risk Level",
            str(
                risk_analysis.get(
                    "risk_level",
                    "MINIMAL",
                )
            ),
        ],
        [
            "Risk Score",
            str(
                risk_analysis.get(
                    "risk_score",
                    0,
                )
            ),
        ],
    ]

    summary_table = Table(
        summary_data,
        colWidths=[65 * mm, 105 * mm],
    )

    summary_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#111827")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
                ("BACKGROUND", (0, 1), (-1, -1), colors.HexColor("#F8FAFC")),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("FONTNAME", (0, 1), (0, -1), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, -1), 8),
                ("TOPPADDING", (0, 0), (-1, -1), 7),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
            ]
        )
    )

    story.append(summary_table)
    story.append(Spacer(1, 10))

    # ========================================================
    # DEVICE IDENTIFICATION
    # ========================================================

    story.append(
        Paragraph(
            "2. Device Identification",
            heading_style,
        )
    )

    hardware = device_info.get(
        "hardware_details",
        {},
    )

    device_data = [
        ["Property", "Value"],
        [
            "Vendor",
            str(
                device_info.get(
                    "vendor",
                    vendor,
                )
            ),
        ],
        [
            "Hostname",
            str(
                device_info.get(
                    "hostname",
                    "Not detected",
                )
            ),
        ],
        [
            "Model",
            str(
                device_info.get(
                    "model",
                    "Not detected",
                )
            ),
        ],
        [
            "Serial Number",
            str(
                device_info.get(
                    "serial_number",
                    "Not detected",
                )
            ),
        ],
        [
            "Software Version",
            str(
                device_info.get(
                    "software_version",
                    "Not detected",
                )
            ),
        ],
        [
            "Memory",
            str(
                hardware.get(
                    "memory",
                    "Not detected",
                )
            ),
        ],
        [
            "Processor",
            str(
                hardware.get(
                    "processor",
                    "Not detected",
                )
            ),
        ],
        [
            "Interfaces",
            str(
                hardware.get(
                    "interfaces",
                    "Not detected",
                )
            ),
        ],
    ]

    device_table = Table(
        device_data,
        colWidths=[55 * mm, 115 * mm],
    )

    device_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#111827")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
                ("BACKGROUND", (0, 1), (-1, -1), colors.white),
                ("FONTNAME", (0, 1), (0, -1), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, -1), 8),
                ("TOPPADDING", (0, 0), (-1, -1), 6),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            ]
        )
    )

    story.append(device_table)

    # ========================================================
    # FINDINGS
    # ========================================================

    story.append(
        Paragraph(
            "3. Compliance Findings",
            heading_style,
        )
    )

    findings_data = [
        [
            "Control",
            "Rule",
            "Status",
            "Severity",
            "Remediation",
        ]
    ]

    for finding in findings:
        findings_data.append(
            [
                Paragraph(
                    str(finding.get("control_id", "-")),
                    small_style,
                ),
                Paragraph(
                    str(finding.get("rule", "-")),
                    small_style,
                ),
                Paragraph(
                    str(finding.get("status", "-")),
                    small_style,
                ),
                Paragraph(
                    str(finding.get("severity", "-")),
                    small_style,
                ),
                Paragraph(
                    str(finding.get("remediation", "-")),
                    small_style,
                ),
            ]
        )

    findings_table = Table(
        findings_data,
        colWidths=[
            22 * mm,
            42 * mm,
            22 * mm,
            22 * mm,
            62 * mm,
        ],
        repeatRows=1,
    )

    findings_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#111827")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("GRID", (0, 0), (-1, -1), 0.4, colors.grey),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("FONTSIZE", (0, 0), (-1, -1), 7),
                ("TOPPADDING", (0, 0), (-1, -1), 5),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ]
        )
    )

    story.append(findings_table)

    # ========================================================
    # CROSS FRAMEWORK
    # ========================================================

    story.append(
        Paragraph(
            "4. Cross-Framework Security Summary",
            heading_style,
        )
    )

    framework_scores = cross_framework.get(
        "framework_scores",
        {},
    )

    framework_data = [
        [
            "Framework",
            "Score",
            "Compliance",
            "Passed",
            "Failed",
            "Unknown",
            "Risk",
        ]
    ]

    for name, result in framework_scores.items():
        framework_data.append(
            [
                str(name),
                str(result.get("security_score", 0)) + "%",
                str(result.get("compliance_percentage", 0)) + "%",
                str(result.get("passed", 0)),
                str(result.get("failed", 0)),
                str(result.get("unknown", 0)),
                str(result.get("risk_level", "-")),
            ]
        )

    if len(framework_data) == 1:
        framework_data.append(
            ["No data", "-", "-", "0", "0", "0", "-"]
        )

    framework_table = Table(
        framework_data,
        colWidths=[
            27 * mm,
            25 * mm,
            27 * mm,
            22 * mm,
            22 * mm,
            22 * mm,
            25 * mm,
        ],
        repeatRows=1,
    )

    framework_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#111827")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
                ("FONTSIZE", (0, 0), (-1, -1), 7.5),
                ("ALIGN", (1, 1), (-1, -1), "CENTER"),
                ("TOPPADDING", (0, 0), (-1, -1), 6),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            ]
        )
    )

    story.append(framework_table)

    # ========================================================
    # RISK ANALYSIS
    # ========================================================

    story.append(
        Paragraph(
            "5. Risk Analysis",
            heading_style,
        )
    )

    severity_counts = risk_analysis.get(
        "severity_counts",
        {},
    )

    risk_data = [
        ["Risk Metric", "Value"],
        [
            "Risk Level",
            str(
                risk_analysis.get(
                    "risk_level",
                    "MINIMAL",
                )
            ),
        ],
        [
            "Risk Score",
            str(
                risk_analysis.get(
                    "risk_score",
                    0,
                )
            ),
        ],
        [
            "Risk Points",
            str(
                risk_analysis.get(
                    "risk_points",
                    0,
                )
            ),
        ],
        [
            "Critical Findings",
            str(
                severity_counts.get(
                    "CRITICAL",
                    0,
                )
            ),
        ],
        [
            "High Findings",
            str(
                severity_counts.get(
                    "HIGH",
                    0,
                )
            ),
        ],
        [
            "Medium Findings",
            str(
                severity_counts.get(
                    "MEDIUM",
                    0,
                )
            ),
        ],
        [
            "Low Findings",
            str(
                severity_counts.get(
                    "LOW",
                    0,
                )
            ),
        ],
        [
            "Failed Controls",
            str(
                risk_analysis.get(
                    "failed_controls",
                    0,
                )
            ),
        ],
    ]

    risk_table = Table(
        risk_data,
        colWidths=[80 * mm, 90 * mm],
    )

    risk_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#111827")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
                ("FONTNAME", (0, 1), (0, -1), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, -1), 8),
                ("TOPPADDING", (0, 0), (-1, -1), 6),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            ]
        )
    )

    story.append(risk_table)

    # ========================================================
    # UNKNOWN CONFIGURATION
    # ========================================================

    story.append(
        Paragraph(
            "6. Unknown Configuration Queue",
            heading_style,
        )
    )

    if unknown_queue:
        unknown_data = [
            [
                "ID",
                "Command",
                "Vendor",
                "Status",
            ]
        ]

        for item in unknown_queue:
            unknown_data.append(
                [
                    str(item.get("id", "-")),
                    Paragraph(
                        str(item.get("command", "-")),
                        small_style,
                    ),
                    str(item.get("vendor", "-")),
                    str(item.get("status", "-")),
                ]
            )

        unknown_table = Table(
            unknown_data,
            colWidths=[
                30 * mm,
                90 * mm,
                25 * mm,
                25 * mm,
            ],
            repeatRows=1,
        )

        unknown_table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#111827")),
                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                    ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                    ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                    ("FONTSIZE", (0, 0), (-1, -1), 7.5),
                    ("TOPPADDING", (0, 0), (-1, -1), 5),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
                ]
            )
        )

        story.append(unknown_table)
    else:
        story.append(
            Paragraph(
                "No unknown configuration detected.",
                normal_style,
            )
        )

    # ========================================================
    # PRIORITY FINDINGS
    # ========================================================

    story.append(
        Paragraph(
            "7. Priority Remediation",
            heading_style,
        )
    )

    priority = compliance_summary.get(
        "priority_findings",
        [],
    )

    if priority:
        priority_data = [
            [
                "Control",
                "Rule",
                "Severity",
                "Recommended Remediation",
            ]
        ]

        for item in priority:
            priority_data.append(
                [
                    str(item.get("control_id", "-")),
                    Paragraph(
                        str(item.get("rule", "-")),
                        small_style,
                    ),
                    str(item.get("severity", "-")),
                    Paragraph(
                        str(item.get("remediation", "-")),
                        small_style,
                    ),
                ]
            )

        priority_table = Table(
            priority_data,
            colWidths=[
                25 * mm,
                45 * mm,
                25 * mm,
                75 * mm,
            ],
            repeatRows=1,
        )

        priority_table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#111827")),
                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                    ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                    ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                    ("FONTSIZE", (0, 0), (-1, -1), 7.5),
                    ("TOPPADDING", (0, 0), (-1, -1), 5),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
                ]
            )
        )

        story.append(priority_table)
    else:
        story.append(
            Paragraph(
                "No failed controls require immediate remediation.",
                normal_style,
            )
        )

    # ========================================================
    # LEARNING SUMMARY
    # ========================================================

    story.append(
        Paragraph(
            "8. AI Learning Summary",
            heading_style,
        )
    )

    learning = analysis.get("learning", {})

    learning_data = [
        ["Learning Metric", "Value"],
        [
            "Total Learned Mappings",
            str(learning.get("total_learned", 0)),
        ],
        [
            "Learned Patterns Used",
            str(learning.get("learned_patterns_used", 0)),
        ],
    ]

    learning_table = Table(
        learning_data,
        colWidths=[80 * mm, 90 * mm],
    )

    learning_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#111827")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
                ("FONTNAME", (0, 1), (0, -1), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, -1), 8),
                ("TOPPADDING", (0, 0), (-1, -1), 6),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            ]
        )
    )

    story.append(learning_table)

    # ========================================================
    # FOOTER
    # ========================================================

    story.append(Spacer(1, 20))

    story.append(
        Paragraph(
            "Generated by NetSentinel AI",
            subtitle_style,
        )
    )

    story.append(
        Paragraph(
            "Generated on "
            + datetime.now().strftime("%d-%m-%Y %H:%M:%S"),
            subtitle_style,
        )
    )

    # ========================================================
    # BUILD PDF
    # ========================================================

    document.build(story)

    return report_path


# ============================================================
# COMPLIANCE REPORT
# ============================================================

@app.post("/report")
async def generate_report(
    file: UploadFile = File(...),
    framework: str = Form("CIS"),
):
    content = await file.read()

    config = content.decode(
        "utf-8",
        errors="ignore",
    )

    analysis = build_complete_analysis(
        file.filename or "configuration.txt",
        config,
        framework,
    )

    report_path = generate_compliance_report(
        analysis
    )

    return FileResponse(
        report_path,
        media_type="application/pdf",
        filename="NetSentinel_Complete_Report.pdf",
        headers={
            "Content-Disposition": (
                'attachment; filename="NetSentinel_Complete_Report.pdf"'
            )
        },
    )


# ============================================================
# RUN WITH:
#
# uvicorn main:app --reload
#
# ============================================================
