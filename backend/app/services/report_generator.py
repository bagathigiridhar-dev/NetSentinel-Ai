"""
NetSentinel AI — PDF Compliance Report Generator Service
"""

import os
from datetime import datetime
from typing import Any, Dict

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
)

from backend.app.config import REPORTS_DIR


def generate_compliance_report(analysis: Dict[str, Any]) -> str:
    """
    Generate an executive PDF compliance report from analysis data.

    Returns the absolute path to the generated PDF file.
    """
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"NetSentinel_Complete_Report_{timestamp}.pdf"
    report_path = str(REPORTS_DIR / filename)

    document = SimpleDocTemplate(
        report_path,
        pagesize=A4,
        rightMargin=15 * mm,
        leftMargin=15 * mm,
        topMargin=15 * mm,
        bottomMargin=15 * mm,
    )

    styles = getSampleStyleSheet()

    title_style = ParagraphStyle(
        "NetSentinelTitle",
        parent=styles["Title"],
        fontSize=24,
        leading=28,
        alignment=TA_CENTER,
        spaceAfter=10,
    )

    subtitle_style = ParagraphStyle(
        "NetSentinelSubtitle",
        parent=styles["Normal"],
        fontSize=11,
        alignment=TA_CENTER,
        textColor=colors.grey,
        spaceAfter=20,
    )

    heading_style = ParagraphStyle(
        "SectionHeading",
        parent=styles["Heading2"],
        fontSize=16,
        leading=20,
        spaceBefore=12,
        spaceAfter=10,
    )

    normal_style = ParagraphStyle(
        "NormalReport",
        parent=styles["Normal"],
        fontSize=9,
        leading=13,
    )

    small_style = ParagraphStyle(
        "SmallReport",
        parent=styles["Normal"],
        fontSize=7.5,
        leading=10,
    )

    story = []

    device = analysis.get("device", "Unknown")
    vendor = analysis.get("vendor", "Unknown")
    framework = analysis.get("framework", "CIS")
    device_info = analysis.get("device_identification", {})
    security_score = analysis.get("security_score", 0)
    risk_analysis = analysis.get("risk_analysis", {})
    findings = analysis.get("findings", [])
    unknown_queue = analysis.get("unknown_configuration_queue", [])
    cross_framework = analysis.get("cross_framework_summary", {})
    compliance_summary = analysis.get("compliance_summary", {})

    # ========================================================
    # TITLE
    # ========================================================

    story.append(Paragraph("NetSentinel AI", title_style))
    story.append(
        Paragraph("Complete Network Security & Compliance Report", subtitle_style)
    )
    story.append(
        Paragraph(
            "AI-Powered Vendor-Agnostic Network Security Compliance Engine",
            subtitle_style,
        )
    )

    # ========================================================
    # 1. EXECUTIVE SUMMARY
    # ========================================================

    story.append(Paragraph("1. Executive Summary", heading_style))

    summary_data = [
        ["Property", "Result"],
        ["Configuration File", str(device)],
        ["Detected Vendor", str(vendor)],
        ["Selected Framework", str(framework)],
        ["Security Score", f"{security_score}%"],
        [
            "Compliance",
            f"{compliance_summary.get('compliance_percentage', 0)}%",
        ],
        [
            "Overall Status",
            str(compliance_summary.get("overall_status", "N/A")),
        ],
        [
            "Risk Level",
            str(risk_analysis.get("risk_level", "MINIMAL")),
        ],
        [
            "Risk Score",
            str(risk_analysis.get("risk_score", 0)),
        ],
    ]

    summary_table = Table(
        summary_data,
        colWidths=[65 * mm, 105 * mm],
    )

    summary_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#111827")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
                ("BACKGROUND", (0, 1), (-1, -1), colors.HexColor("#F8FAFC")),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("FONTNAME", (0, 1), (0, -1), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, -1), 8),
                ("TOPPADDING", (0, 0), (-1, -1), 7),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
            ]
        )
    )

    story.append(summary_table)
    story.append(Spacer(1, 10))

    # ========================================================
    # 2. DEVICE IDENTIFICATION
    # ========================================================

    story.append(Paragraph("2. Device Identification", heading_style))

    hardware = device_info.get("hardware_details", {})

    device_data = [
        ["Property", "Value"],
        ["Vendor", str(device_info.get("vendor", vendor))],
        ["Hostname", str(device_info.get("hostname", "Not detected"))],
        ["Model", str(device_info.get("model", "Not detected"))],
        ["Serial Number", str(device_info.get("serial_number", "Not detected"))],
        ["Software Version", str(device_info.get("software_version", "Not detected"))],
        ["Memory", str(hardware.get("memory", "Not detected"))],
        ["Processor", str(hardware.get("processor", "Not detected"))],
        ["Interfaces", str(hardware.get("interfaces", "Not detected"))],
    ]

    device_table = Table(
        device_data,
        colWidths=[55 * mm, 115 * mm],
    )

    device_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#111827")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
                ("BACKGROUND", (0, 1), (-1, -1), colors.white),
                ("FONTNAME", (0, 1), (0, -1), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, -1), 8),
                ("TOPPADDING", (0, 0), (-1, -1), 6),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            ]
        )
    )

    story.append(device_table)

    # ========================================================
    # 3. COMPLIANCE FINDINGS
    # ========================================================

    story.append(Paragraph("3. Compliance Findings", heading_style))

    findings_data = [
        [
            "Control",
            "Rule",
            "Status",
            "Severity",
            "Remediation",
        ]
    ]

    for finding in findings:
        findings_data.append(
            [
                Paragraph(str(finding.get("control_id", "-")), small_style),
                Paragraph(str(finding.get("rule", "-")), small_style),
                Paragraph(str(finding.get("status", "-")), small_style),
                Paragraph(str(finding.get("severity", "-")), small_style),
                Paragraph(str(finding.get("remediation", "-")), small_style),
            ]
        )

    findings_table = Table(
        findings_data,
        colWidths=[
            22 * mm,
            42 * mm,
            22 * mm,
            22 * mm,
            62 * mm,
        ],
        repeatRows=1,
    )

    findings_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#111827")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("GRID", (0, 0), (-1, -1), 0.4, colors.grey),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("FONTSIZE", (0, 0), (-1, -1), 7),
                ("TOPPADDING", (0, 0), (-1, -1), 5),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ]
        )
    )

    story.append(findings_table)

    # ========================================================
    # 4. CROSS-FRAMEWORK SUMMARY
    # ========================================================

    story.append(Paragraph("4. Cross-Framework Security Summary", heading_style))

    framework_scores = cross_framework.get("framework_scores", {})

    framework_data = [
        [
            "Framework",
            "Score",
            "Compliance",
            "Passed",
            "Failed",
            "Unknown",
            "Risk",
        ]
    ]

    for name, result in framework_scores.items():
        framework_data.append(
            [
                str(name),
                f"{result.get('security_score', 0)}%",
                f"{result.get('compliance_percentage', 0)}%",
                str(result.get("passed", 0)),
                str(result.get("failed", 0)),
                str(result.get("unknown", 0)),
                str(result.get("risk_level", "-")),
            ]
        )

    if len(framework_data) == 1:
        framework_data.append(["No data", "-", "-", "0", "0", "0", "-"])

    framework_table = Table(
        framework_data,
        colWidths=[
            27 * mm,
            25 * mm,
            27 * mm,
            22 * mm,
            22 * mm,
            22 * mm,
            25 * mm,
        ],
        repeatRows=1,
    )

    framework_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#111827")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
                ("FONTSIZE", (0, 0), (-1, -1), 7.5),
                ("ALIGN", (1, 1), (-1, -1), "CENTER"),
                ("TOPPADDING", (0, 0), (-1, -1), 6),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            ]
        )
    )

    story.append(framework_table)

    # ========================================================
    # 5. RISK ANALYSIS
    # ========================================================

    story.append(Paragraph("5. Risk Analysis", heading_style))

    severity_counts = risk_analysis.get("severity_counts", {})

    risk_data = [
        ["Risk Metric", "Value"],
        ["Risk Level", str(risk_analysis.get("risk_level", "MINIMAL"))],
        ["Risk Score", str(risk_analysis.get("risk_score", 0))],
        ["Risk Points", str(risk_analysis.get("risk_points", 0))],
        ["Critical Findings", str(severity_counts.get("CRITICAL", 0))],
        ["High Findings", str(severity_counts.get("HIGH", 0))],
        ["Medium Findings", str(severity_counts.get("MEDIUM", 0))],
        ["Low Findings", str(severity_counts.get("LOW", 0))],
        ["Failed Controls", str(risk_analysis.get("failed_controls", 0))],
    ]

    risk_table = Table(
        risk_data,
        colWidths=[80 * mm, 90 * mm],
    )

    risk_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#111827")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
                ("FONTNAME", (0, 1), (0, -1), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, -1), 8),
                ("TOPPADDING", (0, 0), (-1, -1), 6),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            ]
        )
    )

    story.append(risk_table)

    # ========================================================
    # 6. UNKNOWN CONFIGURATION QUEUE
    # ========================================================

    story.append(Paragraph("6. Unknown Configuration Queue", heading_style))

    if unknown_queue:
        unknown_data = [
            [
                "ID",
                "Command",
                "Vendor",
                "Status",
            ]
        ]

        for item in unknown_queue:
            unknown_data.append(
                [
                    str(item.get("id", "-")),
                    Paragraph(str(item.get("command", "-")), small_style),
                    str(item.get("vendor", "-")),
                    str(item.get("status", "-")),
                ]
            )

        unknown_table = Table(
            unknown_data,
            colWidths=[
                30 * mm,
                90 * mm,
                25 * mm,
                25 * mm,
            ],
            repeatRows=1,
        )

        unknown_table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#111827")),
                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                    ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                    ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                    ("FONTSIZE", (0, 0), (-1, -1), 7.5),
                    ("TOPPADDING", (0, 0), (-1, -1), 5),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
                ]
            )
        )

        story.append(unknown_table)
    else:
        story.append(
            Paragraph("No unknown configuration detected.", normal_style)
        )

    # ========================================================
    # 7. PRIORITY REMEDIATION
    # ========================================================

    story.append(Paragraph("7. Priority Remediation", heading_style))

    priority = compliance_summary.get("priority_findings", [])

    if priority:
        priority_data = [
            [
                "Control",
                "Rule",
                "Severity",
                "Recommended Remediation",
            ]
        ]

        for item in priority:
            priority_data.append(
                [
                    str(item.get("control_id", "-")),
                    Paragraph(str(item.get("rule", "-")), small_style),
                    str(item.get("severity", "-")),
                    Paragraph(str(item.get("remediation", "-")), small_style),
                ]
            )

        priority_table = Table(
            priority_data,
            colWidths=[
                25 * mm,
                45 * mm,
                25 * mm,
                75 * mm,
            ],
            repeatRows=1,
        )

        priority_table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#111827")),
                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                    ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                    ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                    ("FONTSIZE", (0, 0), (-1, -1), 7.5),
                    ("TOPPADDING", (0, 0), (-1, -1), 5),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
                ]
            )
        )

        story.append(priority_table)
    else:
        story.append(
            Paragraph(
                "No failed controls require immediate remediation.",
                normal_style,
            )
        )

    # ========================================================
    # 8. AI LEARNING SUMMARY
    # ========================================================

    story.append(Paragraph("8. AI Learning Summary", heading_style))

    learning = analysis.get("learning", {})

    learning_data = [
        ["Learning Metric", "Value"],
        ["Total Learned Mappings", str(learning.get("total_learned", 0))],
        [
            "Learned Patterns Used",
            str(learning.get("learned_patterns_used", 0)),
        ],
    ]

    learning_table = Table(
        learning_data,
        colWidths=[80 * mm, 90 * mm],
    )

    learning_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#111827")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
                ("FONTNAME", (0, 1), (0, -1), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, -1), 8),
                ("TOPPADDING", (0, 0), (-1, -1), 6),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            ]
        )
    )

    story.append(learning_table)

    # ========================================================
    # FOOTER
    # ========================================================

    story.append(Spacer(1, 20))
    story.append(Paragraph("Generated by NetSentinel AI", subtitle_style))
    story.append(
        Paragraph(
            f"Generated on {datetime.now().strftime('%d-%m-%Y %H:%M:%S')}",
            subtitle_style,
        )
    )

    # ========================================================
    # BUILD PDF
    # ========================================================

    document.build(story)

    return report_path
