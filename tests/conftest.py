"""
Pytest Fixtures for NetSentinel AI Test Suite
"""

import sys
from pathlib import Path
import pytest
from starlette.testclient import TestClient

# Ensure root directory is in python path
ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from backend.app.main import app


@pytest.fixture
def client():
    """FastAPI TestClient fixture."""
    return TestClient(app)


@pytest.fixture
def cisco_config():
    """Sample fully compliant Cisco Router configuration."""
    return """hostname Core-Router-01
version 15.2
ip ssh version 2
line vty 0 4
 transport input ssh
no ip http server
logging buffered
service password-encryption
enable secret SuperSecret123
aaa new-model
snmpv3
ntp server 192.168.1.10
access-list 101 permit ip any any
"""


@pytest.fixture
def insecure_cisco_config():
    """Insecure Cisco configuration failing CIS controls."""
    return """hostname Insecure-Router
version 15.2
ip ssh version 1
line vty 0 4
 transport input telnet
ip http server
no logging
enable password plaintext123
snmp-server community public RO
"""


@pytest.fixture
def paloalto_config():
    """Sample Palo Alto configuration."""
    return """set deviceconfig system type static
set deviceconfig system hostname PA-5020-EDGE
set deviceconfig system ip-address 10.0.0.1
set deviceconfig system panorama-server 10.0.0.254
"""


@pytest.fixture
def unknown_device_config():
    """Sample unknown vendor device configuration."""
    return """DEVICE-OS 7.2
system-name EDGE-UNKNOWN-01
interface ethernet1
 description Uplink
 ip-address 192.168.10.1/24
audit logging disabled
remote-management enabled
"""
