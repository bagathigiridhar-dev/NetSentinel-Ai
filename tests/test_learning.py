"""
Unit tests for NetSentinel AI Dynamic Learning & Token Similarity Matching
"""

import pytest
from backend.app.rules.learned_rules import (
    normalize_command,
    command_similarity,
    add_learned_mapping,
    find_matching_learned_mapping,
    remove_learned_mapping,
    get_learning_statistics,
)


def test_normalize_command():
    cmd = "  SET   SYSTEM   HOST-NAME   test  "
    assert normalize_command(cmd) == "set system host-name test"


def test_command_similarity():
    cmd1 = "ip ssh version 2"
    cmd2 = "ip ssh version 2"
    assert command_similarity(cmd1, cmd2) == 1.0

    cmd3 = "ip ssh version 1"
    assert 0.5 <= command_similarity(cmd1, cmd3) <= 0.8


def test_dynamic_learning_lifecycle():
    test_cmd = "custom-firewall-secure-ssh-v2-enabled"

    # 1. Add mapping
    mapping = add_learned_mapping(
        command=test_cmd,
        category="secure_remote_administration",
        parameter="ssh_version",
        value=2,
        severity="HIGH",
    )
    assert mapping["command"] == test_cmd
    assert mapping["value"] == 2

    # 2. Find exact mapping
    found = find_matching_learned_mapping(test_cmd)
    assert found is not None
    assert found["parameter"] == "ssh_version"
    assert found["value"] == 2

    # 3. Check statistics
    stats = get_learning_statistics()
    assert stats["total"] >= 1

    # 4. Clean up
    removed = remove_learned_mapping(test_cmd)
    assert removed is True
