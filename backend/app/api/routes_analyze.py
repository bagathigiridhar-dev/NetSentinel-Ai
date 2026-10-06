"""
NetSentinel AI — Configuration Analysis & Report Generation Endpoints
"""

from fastapi import APIRouter, File, Form, UploadFile
from fastapi.responses import FileResponse

from backend.app.core.compliance_engine import build_complete_analysis
from backend.app.services.report_generator import generate_compliance_report

router = APIRouter(tags=["Analysis"])


@router.post("/analyze")
async def analyze_config(
    file: UploadFile = File(...),
    framework: str = Form("CIS"),
):
    """
    Analyze a network configuration file against a compliance framework.

    Performs vendor detection, metadata extraction, parameter normalization,
    rule evaluation, risk scoring, and cross-framework analysis.
    """
    content = await file.read()
    config = content.decode("utf-8", errors="ignore")

    return build_complete_analysis(
        filename=file.filename or "configuration.txt",
        config=config,
        framework=framework,
    )


@router.post("/report")
async def generate_report(
    file: UploadFile = File(...),
    framework: str = Form("CIS"),
):
    """
    Analyze a configuration and generate a downloadable executive PDF report.
    """
    content = await file.read()
    config = content.decode("utf-8", errors="ignore")

    analysis = build_complete_analysis(
        filename=file.filename or "configuration.txt",
        config=config,
        framework=framework,
    )

    report_path = generate_compliance_report(analysis)

    return FileResponse(
        path=report_path,
        media_type="application/pdf",
        filename="NetSentinel_Complete_Report.pdf",
        headers={
            "Content-Disposition": (
                'attachment; filename="NetSentinel_Complete_Report.pdf"'
            )
        },
    )
