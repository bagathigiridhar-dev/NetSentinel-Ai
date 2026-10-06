"""
Unit tests for NetSentinel AI Normalization & Security Parameter Extraction
"""

import pytest
from backend.app.core.normalizer import (
    convert_value,
    create_security_parameter,
    extract_device_metadata,
    normalize_configuration,
)


def test_convert_value():
    assert convert_value("true") is True
    assert convert_value("TRUE") is True
    assert convert_value("false") is False
    assert convert_value("FALSE") is False
    assert convert_value("123") == 123
    assert convert_value("45.67") == 45.67
    assert convert_value("hello") == "hello"
    assert convert_value(None) is None
    assert convert_value(True) is True


def test_extract_device_metadata():
    sample = """hostname Edge-Router-01
version 15.4
model ISR4451
serial-number FTX12345678
memory 8GB
processor QuadCore
interfaces GigabitEthernet0/0, GigabitEthernet0/1
"""
    meta = extract_device_metadata(sample, "Cisco")
    assert meta["vendor"] == "Cisco"
    assert meta["hostname"] == "Edge-Router-01"
    assert meta["software_version"] == "15.4"
    assert meta["model"] == "ISR4451"
    assert meta["serial_number"] == "FTX12345678"
    assert meta["hardware_details"]["memory"] == "8GB"
    assert meta["hardware_details"]["processor"] == "QuadCore"
    assert meta["hardware_details"]["interfaces"] == "GigabitEthernet0/0, GigabitEthernet0/1"


def test_normalize_configuration(cisco_config):
    norm = normalize_configuration(cisco_config, "Cisco")
    params = norm["security_parameters"]

    assert params.get("ssh_version") == 2
    assert params.get("telnet_enabled") is False
    assert params.get("logging_enabled") is True
    assert params.get("plaintext_password") is False
    assert params.get("password_encryption_enabled") is True
    assert params.get("aaa_enabled") is True
    assert params.get("snmp_v3_enabled") is True
    assert params.get("ntp_enabled") is True
    assert params.get("access_control_configured") is True


def test_normalize_insecure_configuration(insecure_cisco_config):
    norm = normalize_configuration(insecure_cisco_config, "Cisco")
    params = norm["security_parameters"]

    assert params.get("ssh_version") == 1
    assert params.get("telnet_enabled") is True
    assert params.get("http_enabled") is True
    assert params.get("logging_enabled") is False
    assert params.get("plaintext_password") is True
    assert params.get("snmp_v1_v2_detected") is True
