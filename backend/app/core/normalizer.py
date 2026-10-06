"""
NetSentinel AI — Normalization Engine & Security Baseline Modeler
"""

from typing import Any, Dict, List, Optional
from backend.app.rules.learned_rules import find_matching_learned_mapping


# ============================================================
# VALUE CONVERSION
# ============================================================

def convert_value(value: Any) -> Any:
    """Convert string/raw values to appropriate Python types (bool, int, float, str)."""
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
    category: str,
    parameter: str,
    value: Any,
    vendor: str,
    source: str,
    command: str,
    severity: Optional[str] = None,
) -> Dict[str, Any]:
    """Create a standardized security parameter dictionary."""
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
# DEVICE METADATA EXTRACTION
# ============================================================

def extract_device_metadata(config: str, vendor: str) -> Dict[str, Any]:
    """Extract device identification metadata from raw configuration text."""
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
            metadata["hostname"] = clean.split("set system host-name", 1)[1].strip()

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

def normalize_configuration(config: str, vendor: str) -> Dict[str, Any]:
    """Normalize vendor-specific configuration into a vendor-neutral security model."""
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
        category: str,
        parameter: str,
        value: Any,
        source: str,
        command: str,
        severity: Optional[str] = None,
    ):
        converted = convert_value(value)
        normalized["security_parameters"][parameter] = converted

        normalized["normalized_controls"].append(
            create_security_parameter(
                category,
                parameter,
                converted,
                vendor,
                source,
                command,
                severity,
            )
        )

        normalized["recognized_patterns"].append(
            {
                "parameter": parameter,
                "value": converted,
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
        "parameters_detected": len(normalized["security_parameters"]),
        "normalized_controls": len(normalized["normalized_controls"]),
        "recognized_patterns": len(normalized["recognized_patterns"]),
        "unknown_lines": len(normalized["unknown_lines"]),
        "training_candidates": len(normalized["unknown_objects"]),
    }

    return normalized
