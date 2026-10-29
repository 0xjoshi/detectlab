
from datetime import timezone
from typing import Any

import yaml
from fastapi import HTTPException
from fastapi.encoders import jsonable_encoder
from sqlalchemy.orm import Session

from app.detection.engine import evaluate_threshold
from app.detection.validation import validate_detection
from app.models import Event, Host, Rule, ScenarioRun
from app.schemas import ScenarioRunRequest


def run_scenario(
    db: Session,
    request: ScenarioRunRequest,
    scenario_name: str | None = None,
) -> dict[str, Any]:
    """Ingest scenario events and validate the expected detection."""

    expected_host = (
        db.query(Host)
        .filter(Host.hostname == request.expected_host)
        .first()
    )
    if expected_host is None:
        raise HTTPException(
            status_code=404,
            detail=f"Host '{request.expected_host}' was not found.",
        )

    stored_rule = (
        db.query(Rule)
        .filter(
            Rule.rule_id == request.expected_rule_id,
            Rule.enabled.is_(True),
        )
        .first()
    )
    if stored_rule is None:
        raise HTTPException(
            status_code=404,
            detail=(
                f"Enabled rule '{request.expected_rule_id}' "
                "was not found."
            ),
        )

    try:
        definition = yaml.safe_load(stored_rule.definition_yaml)
    except yaml.YAMLError as exc:
        raise HTTPException(
            status_code=422,
            detail="The expected rule contains invalid YAML.",
        ) from exc

    if not isinstance(definition, dict):
        raise HTTPException(
            status_code=422,
            detail="The rule definition must be a YAML mapping.",
        )

    if definition.get("id") != stored_rule.rule_id:
        raise HTTPException(
            status_code=422,
            detail=(
                "The rule ID in the YAML does not match "
                "the database rule ID."
            ),
        )

    condition = definition.get("condition")
    if (
        not isinstance(condition, dict)
        or condition.get("type") != "threshold"
    ):
        raise HTTPException(
            status_code=422,
            detail=(
                "The expected rule does not use a supported "
                "threshold condition."
            ),
        )

    created_events = []
    scenario_events = []

    try:
        # Ingest and evaluate each event using its actual host.
        for item in request.events:
            event_data = dict(item.event_data)
            event_host_name = event_data.get(
                "host",
                request.expected_host,
            )

            if (
                not isinstance(event_host_name, str)
                or not event_host_name.strip()
            ):
                raise HTTPException(
                    status_code=422,
                    detail=(
                        "Each event host must be a "
                        "non-empty hostname."
                    ),
                )

            event_host = (
                db.query(Host)
                .filter(Host.hostname == event_host_name)
                .first()
            )

            if event_host is None:
                raise HTTPException(
                    status_code=404,
                    detail=f"Host '{event_host_name}' was not found.",
                )

            raw_event = dict(item.raw_event)
            raw_event["scenario_id"] = request.scenario_id

            event_timestamp = item.timestamp.astimezone(timezone.utc)

            event = Event(
                host_id=event_host.id,
                timestamp=event_timestamp,
                event_type=item.event_type,
                event_data=event_data,
                raw_event=raw_event,
            )
            db.add(event)
            created_events.append(event)

            scenario_events.append(
                {
                    "host": event_host.hostname,
                    "timestamp": event_timestamp,
                    "event_type": item.event_type,
                    "event_data": event_data,
                    "raw_event": raw_event,
                }
            )

        db.flush()

        # Evaluate only this scenario's events, not historical events.
        evaluation_time = request.evaluation_time.astimezone(timezone.utc)

        try:
            detections = evaluate_threshold(
                rule=definition,
                events=scenario_events,
                evaluation_time=evaluation_time,
            )
        except ValueError as exc:
            raise HTTPException(
                status_code=422,
                detail=(
                    "The expected rule could not be evaluated: "
                    f"{exc}"
                ),
            ) from exc

        validation = validate_detection(
            expected_rule_id=request.expected_rule_id,
            expected_host=request.expected_host,
            detections=detections,
            expected_detection=request.expected_detection,
        )

        # Save the run and its events in the same transaction.
        run_record = ScenarioRun(
            scenario_id=request.scenario_id,
            scenario_name=scenario_name,
            expected_rule_id=request.expected_rule_id,
            expected_host=request.expected_host,
            evaluation_time=evaluation_time,
            status=validation["status"],
            matched=validation["matched"],
            events_ingested=len(created_events),
            event_ids=[event.id for event in created_events],
            detections=jsonable_encoder(detections),
        )

        db.add(run_record)
        db.flush()
        db.commit()

    except Exception:
        db.rollback()
        raise

    return {
        "run_id": run_record.id,
        "scenario_id": request.scenario_id,
        "scenario_name": scenario_name,
        **validation,
        "evaluation_time": evaluation_time,
        "events_ingested": len(created_events),
        "event_ids": [event.id for event in created_events],
        "detections": detections,
    }