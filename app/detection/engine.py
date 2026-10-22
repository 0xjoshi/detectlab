from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import Any


def _get_event_field(event: dict[str, Any], field: str) -> Any:
    """Resolve event fields from top-level or nested event data."""
    if field == "host":
        return event.get("host")

    if field.startswith("event_data."):
        field = field.removeprefix("event_data.")

    if field in event:
        return event[field]

    value: Any = event.get("event_data", {})
    for part in field.split("."):
        if not isinstance(value, dict) or part not in value:
            return None
        value = value[part]

    return value


def _as_utc(value: datetime) -> datetime:
    """Normalize a timezone-aware datetime to UTC."""
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("Timestamp must be timezone-aware.")
    return value.astimezone(timezone.utc)


def _validate_threshold_rule(rule: dict[str, Any]) -> dict[str, Any]:
    """Validate the configuration required by threshold evaluation."""
    if not isinstance(rule, dict):
        raise ValueError("Rule must be a mapping.")

    rule_id = rule.get("id")
    if not isinstance(rule_id, str) or not rule_id.strip():
        raise ValueError("Rule id must be a non-empty string.")

    condition = rule.get("condition")
    if not isinstance(condition, dict):
        raise ValueError("Rule condition must be a mapping.")

    if condition.get("type") != "threshold":
        raise ValueError("Rule condition type must be threshold.")

    event_type = condition.get("event_type")
    if not isinstance(event_type, str) or not event_type.strip():
        raise ValueError("Threshold event_type must be a non-empty string.")

    count = condition.get("count")
    if type(count) is not int or count <= 0:
        raise ValueError("Threshold count must be a positive integer.")

    window_seconds = condition.get("window_seconds")
    if type(window_seconds) is not int or window_seconds <= 0:
        raise ValueError(
            "Threshold window_seconds must be a positive integer."
        )

    group_by = condition.get("group_by")
    if (
        not isinstance(group_by, list)
        or not group_by
        or any(not isinstance(field, str) or not field.strip()
               for field in group_by)
    ):
        raise ValueError(
            "Threshold group_by must be a non-empty list of field names."
        )

    if len(set(group_by)) != len(group_by):
        raise ValueError("Threshold group_by fields must be unique.")

    return condition


def evaluate_threshold(
    rule: dict[str, Any],
    events: list[dict[str, Any]],
    evaluation_time: datetime,
) -> list[dict[str, Any]]:
    """Evaluate a threshold rule against events in a rolling time window."""
    condition = _validate_threshold_rule(rule)

    if not isinstance(evaluation_time, datetime):
        raise ValueError("Evaluation time must be a datetime.")

    end_time = _as_utc(evaluation_time)
    start_time = end_time - timedelta(
        seconds=condition["window_seconds"]
    )

    event_type = condition["event_type"]
    threshold = condition["count"]
    group_by = condition["group_by"]

    grouped_events: dict[tuple, list[dict[str, Any]]] = defaultdict(list)

    for event in events:
        if not isinstance(event, dict):
            continue

        if event.get("event_type") != event_type:
            continue

        timestamp = event.get("timestamp")
        if not isinstance(timestamp, datetime):
            continue

        # Bad event timestamps are ignored; they do not abort evaluation.
        try:
            event_time = _as_utc(timestamp)
        except ValueError:
            continue

        # Window is open at the start and closed at the evaluation time.
        if not start_time < event_time <= end_time:
            continue

        group_values = {
            field: _get_event_field(event, field)
            for field in group_by
        }

        # Do not combine events with missing grouping values.
        if any(value is None for value in group_values.values()):
            continue

        try:
            group_key = tuple(
                (type(group_values[field]).__name__, group_values[field])
                for field in group_by
            )
            hash(group_key)
        except TypeError:
            # Unhashable grouping values cannot form a stable group key.
            continue

        grouped_events[group_key].append(event)

    detections = []

    for group_key, matching_events in grouped_events.items():
        if len(matching_events) < threshold:
            continue

        group = {
            field: value
            for field, (_, value) in zip(group_by, group_key)
        }

        detections.append(
            {
                "rule_id": rule["id"],
                "count": len(matching_events),
                "threshold": threshold,
                "window_seconds": condition["window_seconds"],
                "window_start": start_time,
                "window_end": end_time,
                "group": group,
            }
        )

    return detections