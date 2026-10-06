"""
NetSentinel AI — System & Health Endpoints
"""

from fastapi import APIRouter
from backend.app.config import APP_NAME, APP_VERSION
from backend.app.rules.learned_rules import load_learned_mappings

router = APIRouter(tags=["System"])


@router.get("/")
def home():
    """Home root endpoint returning service status."""
    return {
        "application": APP_NAME,
        "status": "online",
        "message": "Cybersecurity Compliance Engine is running!",
    }


@router.get("/health")
def health_check():
    """Health check endpoint returning application status and stats."""
    return {
        "status": "healthy",
        "application": APP_NAME,
        "version": APP_VERSION,
        "learned_mappings": len(load_learned_mappings()),
    }


@router.get("/model")
def security_baseline_model():
    """Returns the standardized Vendor-Neutral Security Baseline Model definition."""
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
