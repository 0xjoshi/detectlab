from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator


class HostCreate(BaseModel):
    hostname: str
    platform: str
    ip_address: str | None = None


class HostResponse(BaseModel):
    id: int
    hostname: str
    platform: str
    ip_address: str | None = None

    model_config = ConfigDict(from_attributes=True)


class RuleCreate(BaseModel):
    rule_id: str = Field(min_length=1, max_length=100)
    name: str = Field(min_length=1, max_length=255)
    description: str
    platform: str = Field(min_length=1, max_length=50)
    definition_yaml: str = Field(min_length=1)
    severity: str = Field(min_length=1, max_length=50)
    mitre_technique: str | None = Field(default=None, max_length=50)
    enabled: bool = True


class RuleResponse(BaseModel):
    id: int
    rule_id: str
    name: str
    description: str
    platform: str
    definition_yaml: str
    severity: str
    mitre_technique: str | None = None
    enabled: bool

    model_config = ConfigDict(from_attributes=True)


class EventCreate(BaseModel):
    host_id: int = Field(gt=0)
    timestamp: datetime
    event_type: str = Field(min_length=1, max_length=100)
    event_data: dict[str, Any]
    raw_event: dict[str, Any]

    @field_validator("timestamp")
    @classmethod
    def normalize_timestamp(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("Event timestamp must include a timezone.")
        return value.astimezone(timezone.utc)


class EventResponse(BaseModel):
    id: int
    host_id: int
    timestamp: datetime
    event_type: str
    event_data: dict[str, Any]
    raw_event: dict[str, Any]

    model_config = ConfigDict(from_attributes=True)

class DetectionEvaluationRequest(BaseModel):
    evaluation_time: datetime

    @field_validator("evaluation_time")
    @classmethod
    def require_timezone(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("evaluation_time must include a timezone.")
        return value


class DetectionValidationRequest(DetectionEvaluationRequest):
    expected_rule_id: str = Field(min_length=1, max_length=100)
    expected_host: str = Field(min_length=1, max_length=255)

    @field_validator("expected_rule_id", "expected_host")
    @classmethod
    def require_non_blank(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("This field must not be blank.")
        return value


class ScenarioEventInput(BaseModel):
    timestamp: datetime
    event_type: str = Field(min_length=1, max_length=100)
    event_data: dict[str, Any] = Field(default_factory=dict)
    raw_event: dict[str, Any] = Field(default_factory=dict)

    @field_validator("timestamp")
    @classmethod
    def require_timezone(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("Event timestamp must include a timezone.")
        return value.astimezone(timezone.utc)


class ScenarioRunRequest(BaseModel):
    scenario_id: str = Field(min_length=1, max_length=100)
    expected_rule_id: str = Field(min_length=1, max_length=100)
    expected_host: str = Field(min_length=1, max_length=255)
    evaluation_time: datetime
    events: list[ScenarioEventInput] = Field(min_length=1, max_length=100)

    @field_validator("scenario_id", "expected_rule_id", "expected_host")
    @classmethod
    def require_non_blank(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("This field must not be blank.")
        return value

    @field_validator("evaluation_time")
    @classmethod
    def require_evaluation_timezone(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("Evaluation time must include a timezone.")
        return value

class ScenarioLibraryEvent(BaseModel):
    model_config = ConfigDict(extra="forbid")

    seconds_before_evaluation: int = Field(ge=0, le=86400)
    event_type: str = Field(min_length=1, max_length=100)
    event_data: dict[str, Any] = Field(default_factory=dict)
    raw_event: dict[str, Any] = Field(default_factory=dict)

    @field_validator("event_type")
    @classmethod
    def require_non_blank_event_type(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("event_type must not be blank.")
        return value


class ScenarioLibraryDefinition(BaseModel):
    model_config = ConfigDict(extra="forbid")

    scenario_id: str = Field(min_length=1, max_length=100)
    name: str = Field(min_length=1, max_length=255)
    description: str = Field(min_length=1, max_length=2000)
    expected_rule_id: str = Field(min_length=1, max_length=100)
    expected_host: str = Field(min_length=1, max_length=255)
    events: list[ScenarioLibraryEvent] = Field(min_length=1, max_length=100)

    @field_validator(
        "scenario_id",
        "name",
        "description",
        "expected_rule_id",
        "expected_host",
    )
    @classmethod
    def require_non_blank_values(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("This field must not be blank.")
        return value

class ScenarioRunHistoryItem(BaseModel):
    run_id: int = Field(validation_alias="id")
    scenario_id: str
    scenario_name: str | None = None
    expected_rule_id: str
    expected_host: str
    evaluation_time: datetime
    created_at: datetime
    status: str
    matched: bool
    events_ingested: int
    event_ids: list[int]
    detections: list[dict[str, Any]]

    model_config = ConfigDict(from_attributes=True)


class ScenarioRunHistoryResponse(BaseModel):
    items: list[ScenarioRunHistoryItem]
    total: int
    limit: int
    offset: int
    
class RuleCoverageItem(BaseModel):
    rule_id: str
    rule_name: str
    enabled: bool
    total_runs: int
    pass_count: int
    fail_count: int
    distinct_scenarios: int
    latest_status: str | None = None
    latest_run_at: datetime | None = None
    coverage_status: str


class DetectionCoverageResponse(BaseModel):
    total_rules: int
    tested_rules: int
    untested_rules: int
    coverage_percent: float
    rules: list[RuleCoverageItem]


class RuleRegressionItem(BaseModel):
    rule_id: str
    rule_name: str
    enabled: bool
    total_runs: int
    latest_status: str | None = None
    latest_run_at: datetime | None = None
    latest_scenario_id: str | None = None
    regression_status: str


class RegressionReportResponse(BaseModel):
    total_rules: int
    regression_rules: int
    healthy_rules: int
    untested_rules: int
    rules: list[RuleRegressionItem]