
import yaml


SUPPORTED_CONDITION_TYPES = {"threshold"}
REQUIRED_FIELDS = {
    "id",
    "name",
    "description",
    "platform",
    "condition",
    "severity",
}


class RuleValidationError(ValueError):
    """Raised when a detection rule definition is invalid."""


def validate_rule_definition(
    definition_yaml: str,
    expected_rule_id: str,
    expected_metadata: dict[str, str] | None = None,
) -> dict:
    """Parse and validate a DetectLab YAML rule definition."""

    try:
        definition = yaml.safe_load(definition_yaml)
    except yaml.YAMLError as exc:
        raise RuleValidationError(
            f"Invalid YAML syntax: {exc}"
        ) from exc

    if not isinstance(definition, dict):
        raise RuleValidationError(
            "Rule definition must be a YAML mapping."
        )

    missing_fields = REQUIRED_FIELDS - definition.keys()
    if missing_fields:
        raise RuleValidationError(
            f"Missing required fields: {', '.join(sorted(missing_fields))}"
        )

    for field in ("id", "name", "description", "platform", "severity"):
        value = definition[field]
        if not isinstance(value, str) or not value.strip():
            raise RuleValidationError(
                f"Field '{field}' must be a non-empty string."
            )

    if definition["id"] != expected_rule_id:
        raise RuleValidationError(
            "YAML rule id must match the API rule_id."
        )

    # Ensure YAML metadata matches the API request.
    if expected_metadata is not None:
        for field, expected_value in expected_metadata.items():
            if definition[field] != expected_value:
                raise RuleValidationError(
                    f"YAML field '{field}' must match the API {field}."
                )

    condition = definition["condition"]
    if not isinstance(condition, dict):
        raise RuleValidationError(
            "The condition field must be a YAML mapping."
        )

    condition_type = condition.get("type")
    if condition_type not in SUPPORTED_CONDITION_TYPES:
        raise RuleValidationError(
            "Unsupported condition type. Supported types: threshold"
        )

    if condition_type == "threshold":
        event_type = condition.get("event_type")
        count = condition.get("count")
        window_seconds = condition.get("window_seconds")
        group_by = condition.get("group_by")

        if not isinstance(event_type, str) or not event_type.strip():
            raise RuleValidationError(
                "Threshold conditions require a non-empty event_type."
            )

        # bool is a subclass of int in Python, so reject it explicitly.
        if type(count) is not int or count <= 0:
            raise RuleValidationError(
                "Threshold count must be a positive integer."
            )

        if type(window_seconds) is not int or window_seconds <= 0:
            raise RuleValidationError(
                "Threshold window_seconds must be a positive integer."
            )

        if (
            not isinstance(group_by, list)
            or not group_by
            or any(
                not isinstance(field, str) or not field.strip()
                for field in group_by
            )
        ):
            raise RuleValidationError(
                "Threshold group_by must be a non-empty list of field names."
            )

        if len(set(group_by)) != len(group_by):
            raise RuleValidationError(
                "Threshold group_by must not contain duplicate field names."
            )

        distinct_field = condition.get("distinct_field")
        if distinct_field is not None:
            if not isinstance(distinct_field, str) or not distinct_field.strip():
                raise RuleValidationError(
                    "Threshold distinct_field must be a non-empty string."
                )

            if distinct_field in group_by:
                raise RuleValidationError(
                    "Threshold distinct_field must not also be a "
                    "group_by field."
                )

    return definition
