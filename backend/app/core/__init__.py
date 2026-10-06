"""
NetSentinel AI — Core Analysis & Normalization Engines
"""

from backend.app.core.vendor_detector import detect_vendor
from backend.app.core.normalizer import (
    convert_value,
    create_security_parameter,
    extract_device_metadata,
    normalize_configuration,
)
from backend.app.core.compliance_engine import (
    evaluate_normalized_control,
    evaluate_framework,
    build_compliance_summary,
    build_framework_summary,
    build_cross_framework_summary,
    build_complete_analysis,
)
from backend.app.core.risk_engine import (
    RISK_WEIGHTS,
    calculate_risk,
    calculate_security_score,
)

__all__ = [
    "detect_vendor",
    "convert_value",
    "create_security_parameter",
    "extract_device_metadata",
    "normalize_configuration",
    "evaluate_normalized_control",
    "evaluate_framework",
    "build_compliance_summary",
    "build_framework_summary",
    "build_cross_framework_summary",
    "build_complete_analysis",
    "RISK_WEIGHTS",
    "calculate_risk",
    "calculate_security_score",
]
