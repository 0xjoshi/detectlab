
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

    host = (
        db.query(Host)
        .filter(Host.hostname == request.expected_host)
        .first()
    )
    if host is None:
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
            detail="The rule ID in the YAML does not match the database rule ID.",
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

    try:
        # Persist scenario events with a traceable scenario ID.
        for item in request.events:
            raw_event = dict(item.raw_event)
            raw_event["scenario_id"] = request.scenario_id

            event = Event(
                host_id=host.id,
                timestamp=item.timestamp.astimezone(timezone.utc),
                event_type=item.event_type,
                event_data=item.event_data,
                raw_event=raw_event,
            )
            db.add(event)
            created_events.append(event)

        db.flush()

        # Evaluate only this request's events, not historical events.
        scenario_events = [
            {
                "host": host.hostname,
                "timestamp": item.timestamp.astimezone(timezone.utc),
                "event_type": item.event_type,
                "event_data": item.event_data,
                "raw_event": {
                    **item.raw_event,
                    "scenario_id": request.scenario_id,
                },
            }
            for item in request.events
        ]

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
                detail=f"The expected rule could not be evaluated: {exc}",
            ) from exc

        validation = validate_detection(
            expected_rule_id=request.expected_rule_id,
            expected_host=request.expected_host,
            detections=detections,
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