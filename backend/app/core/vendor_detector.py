"""
NetSentinel AI — Vendor Detection Engine
"""


def detect_vendor(config: str) -> str:
    """
    Detect the network device vendor from configuration text.

    Supports Cisco, Juniper, Fortinet, Palo Alto, Arista, SONiC, and Unknown.
    """
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
