"""
NetSentinel AI — Dynamic Rule Training & Knowledge Base Endpoints
"""

from fastapi import APIRouter, Form
from backend.app.core.normalizer import convert_value
from backend.app.rules.learned_rules import (
    add_learned_mapping,
    load_learned_mappings,
    get_learning_statistics,
)

router = APIRouter(tags=["Learning"])


@router.post("/train")
async def train_configuration(
    command: str = Form(...),
    category: str = Form(...),
    parameter: str = Form(...),
    value: str = Form(...),
    severity: str = Form("MEDIUM"),
):
    """
    Train NetSentinel with new vendor syntax mappings.
    Learned rules persist and are utilized in subsequent analyses.
    """
    command = command.strip()
    category = category.strip()
    parameter = parameter.strip()
    value = value.strip()
    severity = severity.upper().strip()

    if not command:
        return {
            "success": False,
            "message": "Command is required.",
        }

    if not category:
        return {
            "success": False,
            "message": "Category is required.",
        }

    if not parameter:
        return {
            "success": False,
            "message": "Parameter is required.",
        }

    if not value:
        return {
            "success": False,
            "message": "Value is required.",
        }

    allowed_severities = {
        "CRITICAL",
        "HIGH",
        "MEDIUM",
        "LOW",
        "INFO",
    }

    if severity not in allowed_severities:
        severity = "MEDIUM"

    final_value = convert_value(value)

    mapping = add_learned_mapping(
        command=command,
        category=category,
        parameter=parameter,
        value=final_value,
        severity=severity,
    )

    saved_mappings = load_learned_mappings()

    return {
        "success": True,
        "message": "NetSentinel learned the new configuration pattern.",
        "learning": mapping,
        "total_learned": len(saved_mappings),
    }


@router.get("/learned")
def get_learned_mappings():
    """Retrieve all active learned command mappings."""
    mappings = load_learned_mappings()
    return {
        "count": len(mappings),
        "mappings": mappings,
    }


@router.get("/learning/stats")
def learning_statistics():
    """Retrieve summary statistics of dynamic learning repository."""
    return get_learning_statistics()
