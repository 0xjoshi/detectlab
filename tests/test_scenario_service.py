
from datetime import datetime, timedelta, timezone

import pytest
import yaml
from fastapi import HTTPException
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.database import Base
from app.detection.scenario import run_scenario
from app.models import Event, Host, Rule
from app.schemas import ScenarioRunRequest


@pytest.fixture
def db():
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    TestingSessionLocal = sessionmaker(
        bind=engine,
        autoflush=False,
        autocommit=False,
    )
    Base.metadata.create_all(bind=engine)

    session = TestingSessionLocal()
    session.add(
        Host(
            id=1,
            hostname="WIN11-LAB",
            platform="windows",
            ip_address="192.168.56.10",
        )
    )

    definition = {
        "id": "DET-001",
        "name": "Multiple Failed Logins",
        "description": "Detect repeated authentication failures",
        "platform": "windows",
        "severity": "medium",
        "condition": {
            "type": "threshold",
            "event_type": "authentication_failure",
            "count": 3,
            "window_seconds": 60,
            "group_by": ["host", "user"],
        },
    }
    session.add(
        Rule(
            rule_id="DET-001",
            name="Multiple Failed Logins",
            description="Detect repeated authentication failures",
            platform="windows",
            definition_yaml=yaml.safe_dump(definition),
            severity="medium",
            enabled=True,
        )
    )
    session.commit()

    try:
        yield session
    finally:
        session.close()
        Base.metadata.drop_all(bind=engine)
        engine.dispose()


def make_request(event_count=3, rule_id="DET-001", host="WIN11-LAB"):
    evaluation_time = datetime(2026, 10, 22, 16, 0, tzinfo=timezone.utc)
    events = [
        {
            "timestamp": (
                evaluation_time - timedelta(seconds=10 * (event_count - i))
            ).isoformat(),
            "event_type": "authentication_failure",
            "event_data": {
                "user": "scenario-test-user",
                "status": "failure",
            },
            "raw_event": {"source": "scenario-test"},
        }
        for i in range(event_count)
    ]

    return ScenarioRunRequest(
        scenario_id="SCN-001",
        expected_rule_id=rule_id,
        expected_host=host,
        evaluation_time=evaluation_time,
        events=events,
    )


def test_run_scenario_passes_when_threshold_is_met(db):
    result = run_scenario(db, make_request())

    assert result["status"] == "PASS"
    assert result["matched"] is True
    assert result["scenario_id"] == "SCN-001"
    assert result["events_ingested"] == 3
    assert len(result["event_ids"]) == 3
    assert result["detections"][0]["rule_id"] == "DET-001"
    assert result["detections"][0]["count"] == 3


def test_run_scenario_fails_when_threshold_is_not_met(db):
    result = run_scenario(db, make_request(event_count=2))

    assert result["status"] == "FAIL"
    assert result["matched"] is False
    assert result["events_ingested"] == 2
    assert result["detections"] == []


def test_run_scenario_does_not_pass_from_historical_events(db):
    evaluation_time = datetime(
        2026, 10, 22, 16, 0, tzinfo=timezone.utc
    )
    for seconds_ago in (10, 20, 30):
        db.add(
            Event(
                host_id=1,
                timestamp=evaluation_time - timedelta(seconds=seconds_ago),
                event_type="authentication_failure",
                event_data={"user": "historical-user"},
                raw_event={"source": "historical"},
            )
        )
    db.commit()

    result = run_scenario(db, make_request(event_count=2))

    assert result["status"] == "FAIL"
    assert result["detections"] == []


def test_run_scenario_rejects_unknown_host(db):
    with pytest.raises(HTTPException) as exc_info:
        run_scenario(db, make_request(host="UNKNOWN-HOST"))

    assert exc_info.value.status_code == 404


def test_run_scenario_rejects_unknown_rule(db):
    with pytest.raises(HTTPException) as exc_info:
        run_scenario(db, make_request(rule_id="DET-999"))

    assert exc_info.value.status_code == 404

def test_run_scenario_rejects_mismatched_yaml_rule_id(db):
    stored_rule = db.query(Rule).filter(
        Rule.rule_id == "DET-001"
    ).first()

    definition = yaml.safe_load(stored_rule.definition_yaml)
    definition["id"] = "DET-999"
    stored_rule.definition_yaml = yaml.safe_dump(definition)
    db.commit()

    with pytest.raises(HTTPException) as exc_info:
        run_scenario(db, make_request())

    assert exc_info.value.status_code == 422
    assert db.query(Event).count() == 0


def test_run_scenario_rolls_back_events_when_evaluation_fails(db):
    stored_rule = db.query(Rule).filter(
        Rule.rule_id == "DET-001"
    ).first()

    definition = yaml.safe_load(stored_rule.definition_yaml)
    definition["condition"]["count"] = 0
    stored_rule.definition_yaml = yaml.safe_dump(definition)
    db.commit()

    with pytest.raises(HTTPException) as exc_info:
        run_scenario(db, make_request())

    assert exc_info.value.status_code == 422
    assert db.query(Event).count() == 0