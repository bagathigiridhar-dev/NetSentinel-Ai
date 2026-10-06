"""
NetSentinel AI — Learned Rules & Dynamic Training Engine
"""

import json
import os
import re
from pathlib import Path
from backend.app.config import DATA_DIR

LEARNED_RULES_FILE = DATA_DIR / "learned_mappings.json"


# ============================================================
# ENSURE STORAGE EXISTS
# ============================================================

def ensure_storage():
    """Ensure the data directory and learned mappings file exist."""
    DATA_DIR.mkdir(parents=True, exist_ok=True)

    if not os.path.exists(LEARNED_RULES_FILE):
        with open(LEARNED_RULES_FILE, "w", encoding="utf-8") as file:
            json.dump([], file, indent=2)


# ============================================================
# LOAD LEARNED MAPPINGS
# ============================================================

def load_learned_mappings():
    """Load learned mappings from persistent JSON storage."""
    ensure_storage()

    try:
        with open(LEARNED_RULES_FILE, "r", encoding="utf-8") as file:
            data = json.load(file)
            if isinstance(data, list):
                return data
            return []
    except (json.JSONDecodeError, OSError):
        return []


# ============================================================
# NORMALIZE COMMAND FOR MATCHING
# ============================================================

def normalize_command(command):
    """Normalize a command string by lowercasing and condensing whitespace."""
    if command is None:
        return ""

    command = str(command).strip().lower()
    command = re.sub(r"\s+", " ", command)
    return command


# ============================================================
# COMMAND TOKEN SIMILARITY
# ============================================================

def command_similarity(command_a, command_b):
    """Calculate token-level Jaccard similarity between two command strings."""
    a = set(normalize_command(command_a).split())
    b = set(normalize_command(command_b).split())

    if not a or not b:
        return 0.0

    intersection = len(a.intersection(b))
    union = len(a.union(b))

    return intersection / union


# ============================================================
# FIND MATCHING LEARNED MAPPING
# ============================================================

def find_matching_learned_mapping(command):
    """
    Find a matching learned mapping for a given command.
    Checks exact matches first, then falls back to similarity >= 0.75.
    """
    mappings = load_learned_mappings()
    normalized_command = normalize_command(command)

    # 1. Exact match
    for mapping in mappings:
        learned_command = normalize_command(mapping.get("command", ""))
        if learned_command and learned_command == normalized_command:
            return mapping

    # 2. Similarity match (Jaccard >= 0.75)
    best_mapping = None
    best_score = 0.0

    for mapping in mappings:
        learned_command = mapping.get("command", "")
        score = command_similarity(command, learned_command)
        if score > best_score:
            best_score = score
            best_mapping = mapping

    if best_mapping and best_score >= 0.75:
        return best_mapping

    return None


# ============================================================
# ADD LEARNED MAPPING
# ============================================================

def add_learned_mapping(
    command,
    category,
    parameter,
    value,
    severity="MEDIUM",
):
    """Add or update a learned command mapping in storage."""
    mappings = load_learned_mappings()
    normalized_command = normalize_command(command)

    # Update existing mapping if command matches
    for mapping in mappings:
        if normalize_command(mapping.get("command", "")) == normalized_command:
            mapping["category"] = category
            mapping["parameter"] = parameter
            mapping["value"] = value
            mapping["severity"] = severity
            mapping["source"] = "administrator_training"
            mapping["status"] = "active"

            with open(LEARNED_RULES_FILE, "w", encoding="utf-8") as file:
                json.dump(mappings, file, indent=2)

            return mapping

    # Create new mapping
    mapping = {
        "command": command,
        "normalized_command": normalized_command,
        "category": category,
        "parameter": parameter,
        "value": value,
        "severity": severity,
        "source": "administrator_training",
        "status": "active",
    }

    mappings.append(mapping)

    with open(LEARNED_RULES_FILE, "w", encoding="utf-8") as file:
        json.dump(mappings, file, indent=2)

    return mapping


# ============================================================
# REMOVE LEARNED MAPPING
# ============================================================

def remove_learned_mapping(command):
    """Remove a learned mapping by its command string."""
    mappings = load_learned_mappings()
    normalized_command = normalize_command(command)

    updated = []
    removed = False

    for mapping in mappings:
        if normalize_command(mapping.get("command", "")) == normalized_command:
            removed = True
            continue
        updated.append(mapping)

    with open(LEARNED_RULES_FILE, "w", encoding="utf-8") as file:
        json.dump(updated, file, indent=2)

    return removed


# ============================================================
# LEARNING STATISTICS
# ============================================================

def get_learning_statistics():
    """Return summary statistics of all learned rules."""
    mappings = load_learned_mappings()
    categories = {}
    parameters = {}

    for mapping in mappings:
        category = mapping.get("category", "unknown")
        parameter = mapping.get("parameter", "unknown")

        categories[category] = categories.get(category, 0) + 1
        parameters[parameter] = parameters.get(parameter, 0) + 1

    return {
        "total": len(mappings),
        "categories": categories,
        "parameters": parameters,
    }
