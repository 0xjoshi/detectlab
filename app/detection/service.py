from datetime import datetime, timezone
from typing import Any

import yaml
from sqlalchemy.orm import Session

from app.detection.engine import evaluate_threshold
from app.models import Event, Host, Rule


def evaluate_enabled_rules(
    db: Session,
    evaluation_time: datetime,
) -> dict[str, Any]:
    """Evaluate enabled threshold rules against stored events."""

    if evaluation_time.tzinfo is None or evaluation_time.utcoffset() is None:
        raise ValueError("Evaluation time must include a timezone.")

    evaluation_time = evaluation_time.astimezone(timezone.utc)

    stored_events = (
        db.query(Event, Host.hostname)
        .join(Host, Event.host_id == Host.id)
        .all()
    )

    events = []

    for event, hostname in stored_events:
        timestamp = event.timestamp

        # SQLite may return timestamps without timezone information.
        # Stored event timestamps are treated as UTC in that case.
        if timestamp.tzinfo is None or timestamp.utcoffset() is None:
            timestamp = timestamp.replace(tzinfo=timezone.utc)
        else:
            timestamp = timestamp.astimezone(timezone.utc)

        events.append(
            {
                "host": hostname,
                "timestamp": timestamp,
                "event_type": event.event_type,
                "event_data": event.event_data,
                "raw_event": event.raw_event,
            }
        )

    rules = (
        db.query(Rule)
        .filter(Rule.enabled.is_(True))
        .order_by(Rule.id)
        .all()
    )

    detections = []
    rules_evaluated = 0
    rules_skipped = []

    for stored_rule in rules:
        try:
            definition = yaml.safe_load(stored_rule.definition_yaml)
        except yaml.YAMLError:
            rules_skipped.append(
                {
                    "rule_id": stored_rule.rule_id,
                    "reason": "Invalid YAML",
                }
            )
            continue

        if not isinstance(definition, dict):
            rules_skipped.append(
                {
                    "rule_id": stored_rule.rule_id,
                    "reason": "Rule definition must be a YAML mapping",
                }
            )
            continue

        condition = definition.get("condition")

        if not isinstance(condition, dict):
            rules_skipped.append(
                {
                    "rule_id": stored_rule.rule_id,
                    "reason": "Missing or invalid condition",
                }
            )
            continue

        if condition.get("type") != "threshold":
            rules_skipped.append(
                {
                    "rule_id": stored_rule.rule_id,
                    "reason": "Unsupported condition type",
                }
            )
            continue

        try:
            rule_detections = evaluate_threshold(
                rule=definition,
                events=events,
                evaluation_time=evaluation_time,
            )
        except ValueError as exc:
            rules_skipped.append(
                {
                    "rule_id": stored_rule.rule_id,
                    "reason": str(exc),
                }
            )
            continue

        rules_evaluated += 1
        detections.extend(rule_detections)

    return {
        "evaluation_time": evaluation_time,
        "rules_evaluated": rules_evaluated,
        "rules_skipped": rules_skipped,
        "detections": detections,
    }