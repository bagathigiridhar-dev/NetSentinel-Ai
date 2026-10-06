"""
NetSentinel AI — Legacy Entrypoint & Backward-Compatibility Wrapper
"""

import sys
from pathlib import Path

# Ensure root directory is on Python path for legacy invocations
ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from backend.app.main import app, create_app
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
from backend.app.rules.compliance_rules import COMPLIANCE_RULES
from backend.app.rules.learned_rules import (
    add_learned_mapping,
    find_matching_learned_mapping,
    load_learned_mappings,
    get_learning_statistics,
)
from backend.app.services.report_generator import generate_compliance_report

__all__ = [
    "app",
    "create_app",
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
    "COMPLIANCE_RULES",
    "add_learned_mapping",
    "find_matching_learned_mapping",
    "load_learned_mappings",
    "get_learning_statistics",
    "generate_compliance_report",
]

if __name__ == "__main__":
    import uvicorn
    from backend.app.config import HOST, PORT, RELOAD
    uvicorn.run("backend.app.main:app", host=HOST, port=PORT, reload=RELOAD)
