
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import yaml
from fastapi import HTTPException
from pydantic import ValidationError
from sqlalchemy.orm import Session

from app.detection.scenario import run_scenario
from app.schemas import (
    ScenarioLibraryDefinition,
    ScenarioRunRequest,
)


SCENARIO_DIRECTORY = Path(__file__).resolve().parents[2] / "scenarios"
SCENARIO_ID_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,99}")


class UniqueKeySafeLoader(yaml.SafeLoader):
    """Safe YAML loader that rejects duplicate mapping keys."""


def _construct_unique_mapping(
    loader: UniqueKeySafeLoader,
    node: yaml.MappingNode,
    deep: bool = False,
) -> dict[str, Any]:
    mapping = {}

    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)

        try:
            duplicate = key in mapping
        except TypeError as exc:
            raise yaml.constructor.ConstructorError(
                None,
                None,
                "YAML mapping keys must be hashable.",
                key_node.start_mark,
            ) from exc

        if duplicate:
            raise yaml.constructor.ConstructorError(
                None,
                None,
                f"Duplicate YAML key: {key!r}",
                key_node.start_mark,
            )

        mapping[key] = loader.construct_object(value_node, deep=deep)

    return mapping


UniqueKeySafeLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
    _construct_unique_mapping,
)


def load_scenario_definition(
    scenario_id: str,
) -> ScenarioLibraryDefinition:
    """Load and validate a scenario selected by its ID."""

    if not SCENARIO_ID_PATTERN.fullmatch(scenario_id):
        raise HTTPException(
            status_code=422,
            detail="Invalid scenario ID format.",
        )

    scenario_path = SCENARIO_DIRECTORY / f"{scenario_id}.yaml"

    if not scenario_path.is_file():
        raise HTTPException(
            status_code=404,
            detail=f"Scenario '{scenario_id}' was not found.",
        )

    try:
        with scenario_path.open("r", encoding="utf-8") as file:
            data = yaml.load(file, Loader=UniqueKeySafeLoader)
    except (yaml.YAMLError, UnicodeError) as exc:
        raise HTTPException(
            status_code=422,
            detail="Scenario file contains invalid YAML or text encoding.",
        ) from exc
    except OSError as exc:
        raise HTTPException(
            status_code=422,
            detail="Scenario file could not be read.",
        ) from exc

    try:
        definition = ScenarioLibraryDefinition.model_validate(data)
    except ValidationError as exc:
        raise HTTPException(
            status_code=422,
            detail=f"Invalid scenario definition: {exc}",
        ) from exc

    if definition.scenario_id != scenario_id:
        raise HTTPException(
            status_code=422,
            detail="Scenario ID in the file does not match its filename.",
        )

    return definition


def run_library_scenario(
    db: Session,
    scenario_id: str,
) -> dict[str, Any]:
    """Run a validated YAML scenario using the existing runner."""

    definition = load_scenario_definition(scenario_id)
    evaluation_time = datetime.now(timezone.utc)

    request = ScenarioRunRequest(
        scenario_id=definition.scenario_id,
        expected_rule_id=definition.expected_rule_id,
        expected_host=definition.expected_host,
        evaluation_time=evaluation_time,
        events=[
            {
                "timestamp": evaluation_time
                - timedelta(seconds=event.seconds_before_evaluation),
                "event_type": event.event_type,
                "event_data": event.event_data,
                "raw_event": event.raw_event,
            }
            for event in definition.events
        ],
    )

    result = run_scenario(db=db, request=request)
    result["scenario_name"] = definition.name
    return result
