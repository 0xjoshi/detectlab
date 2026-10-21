
import pytest

from app.detection.rule_validator import (
    RuleValidationError,
    validate_rule_definition,
)


VALID_YAML = """
id: DET-001
name: Test Rule
description: Test description
platform: windows
severity: medium
condition:
  type: threshold
  event_type: authentication_failure
  count: 5
  window_seconds: 60
  group_by: [host, user]
"""


def test_valid_rule_is_accepted():
    result = validate_rule_definition(VALID_YAML, "DET-001")
    assert result["id"] == "DET-001"


def test_matching_metadata_is_accepted():
    validate_rule_definition(
        VALID_YAML,
        "DET-001",
        {
            "name": "Test Rule",
            "description": "Test description",
            "platform": "windows",
            "severity": "medium",
        },
    )


def test_mismatched_metadata_is_rejected():
    with pytest.raises(RuleValidationError, match="platform"):
        validate_rule_definition(
            VALID_YAML,
            "DET-001",
            {"platform": "linux"},
        )


def test_mismatched_rule_id_is_rejected():
    with pytest.raises(RuleValidationError, match="rule id"):
        validate_rule_definition(VALID_YAML, "DET-999")


def test_invalid_yaml_is_rejected():
    with pytest.raises(RuleValidationError, match="Invalid YAML syntax"):
        validate_rule_definition("id: [invalid", "DET-001")


def test_non_mapping_yaml_is_rejected():
    with pytest.raises(RuleValidationError, match="YAML mapping"):
        validate_rule_definition("- one\n- two", "DET-001")


def test_missing_required_field_is_rejected():
    incomplete_yaml = """
id: DET-001
name: Test Rule
description: Test description
platform: windows
severity: medium
"""
    with pytest.raises(RuleValidationError, match="Missing required fields"):
        validate_rule_definition(incomplete_yaml, "DET-001")


def test_unsupported_condition_type_is_rejected():
    invalid_yaml = VALID_YAML.replace(
        "type: threshold",
        "type: unknown",
    )
    with pytest.raises(RuleValidationError, match="Unsupported condition type"):
        validate_rule_definition(invalid_yaml, "DET-001")


def test_invalid_threshold_count_is_rejected():
    invalid_yaml = VALID_YAML.replace("count: 5", "count: 0")
    with pytest.raises(RuleValidationError, match="positive integer"):
        validate_rule_definition(invalid_yaml, "DET-001")


def test_invalid_threshold_window_is_rejected():
    invalid_yaml = VALID_YAML.replace(
        "window_seconds: 60",
        "window_seconds: -1",
    )
    with pytest.raises(RuleValidationError, match="window_seconds"):
        validate_rule_definition(invalid_yaml, "DET-001")
