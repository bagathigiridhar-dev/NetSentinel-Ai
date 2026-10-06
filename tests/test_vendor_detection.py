"""
Unit tests for NetSentinel AI Vendor Detection
"""

import pytest
from backend.app.core.vendor_detector import detect_vendor


def test_detect_cisco():
    cisco_sample = "hostname R1\ninterface GigabitEthernet0/0\nline vty 0 4"
    assert detect_vendor(cisco_sample) == "Cisco"

    cisco_version = "Cisco IOS Software, Version 15.2(4)M1"
    assert detect_vendor(cisco_version) == "Cisco"


def test_detect_juniper():
    juniper_sample = "set system host-name core-switch-01\nset interfaces ge-0/0/0 unit 0"
    assert detect_vendor(juniper_sample) == "Juniper"


def test_detect_fortinet():
    fortinet_sample = "config system global\n    set hostname FGT-60F\nend"
    assert detect_vendor(fortinet_sample) == "Fortinet"


def test_detect_palo_alto():
    pa_sample = "set deviceconfig system hostname PA-EDGE-01"
    assert detect_vendor(pa_sample) == "Palo Alto"

    pa_xml = '<entry name="rule1"><action>allow</action></entry>'
    assert detect_vendor(pa_xml) == "Palo Alto"


def test_detect_arista():
    arista_sample = "! Arista EOS version 4.25.0F\nhostname arista-sw01"
    assert detect_vendor(arista_sample) == "Arista"


def test_detect_sonic():
    sonic_sample = "sonic_version: 202111.00\nhostname: sonic-leaf01"
    assert detect_vendor(sonic_sample) == "SONiC"


def test_detect_unknown():
    unknown_sample = "DEVICE-OS 7.2\nsystem-name TEST-DEVICE\nfeature x enable"
    assert detect_vendor(unknown_sample) == "Unknown"
