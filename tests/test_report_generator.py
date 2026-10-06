"""
Unit tests for NetSentinel AI PDF Report Generation Service
"""

import os
from pathlib import Path
import pytest
from backend.app.core.compliance_engine import build_complete_analysis
from backend.app.services.report_generator import generate_compliance_report


def test_generate_pdf_report(cisco_config):
    analysis = build_complete_analysis("test_router.txt", cisco_config, "CIS")
    pdf_path = generate_compliance_report(analysis)

    assert os.path.exists(pdf_path)
    assert pdf_path.endswith(".pdf")
    assert os.path.getsize(pdf_path) > 1000

    # Verify PDF magic header
    with open(pdf_path, "rb") as f:
        header = f.read(5)
        assert header == b"%PDF-"
