
from datetime import datetime, timedelta, timezone

import pytest
import yaml
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.database import Base
from app.detection.service import evaluate_enabled_rules
from app.models import Event, Host, Rule


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

    session.commit()

    try:
        yield session
    finally:
        session.close()
        Base.metadata.drop_all(bind=engine)
        engine.dispose()


def make_rule(
    db,
    rule_id="DET-001",
    enabled=True,
    window_seconds=60,
    count=3,
):
    definition = {
        "id": rule_id,
        "name": "Multiple Failed Logins",
        "description": "Detect repeated authentication failures",
        "platform": "windows",
        "severity": "medium",
        "condition": {
            "type": "threshold",
            "event_type": "authentication_failure",
            "count": count,
            "window_seconds": window_seconds,
            "group_by": ["host", "user"],
        },
    }

    db.add(
        Rule(
            rule_id=rule_id,
            name=definition["name"],
            description=definition["description"],
            platform=definition["platform"],
            definition_yaml=yaml.safe_dump(definition),
            severity=definition["severity"],
            enabled=enabled,
        )
    )
    db.commit()


def add_event(
    db,
    timestamp,
    user="labuser",
    event_type="authentication_failure",
):
    db.add(
        Event(
            host_id=1,
            timestamp=timestamp,
            event_type=event_type,
            event_data={"user": user},
            raw_event={"source": "test"},
        )
    )
    db.commit()


def test_evaluates_enabled_rule_and_detects_threshold(db):
    evaluation_time = datetime(2026, 10, 23, 12, 0, tzinfo=timezone.utc)
    make_rule(db)

    for seconds_ago in (30, 20, 10):
        add_event(db, evaluation_time - timedelta(seconds=seconds_ago))

    result = evaluate_enabled_rules(db, evaluation_time)

    assert result["rules_evaluated"] == 1
    assert result["rules_skipped"] == []
    assert len(result["detections"]) == 1
    assert result["detections"][0]["rule_id"] == "DET-001"
    assert result["detections"][0]["count"] == 3


def test_disabled_rule_is_not_evaluated(db):
    evaluation_time = datetime(2026, 10, 23, 12, 0, tzinfo=timezone.utc)
    make_rule(db, enabled=False)

    for seconds_ago in (30, 20, 10):
        add_event(db, evaluation_time - timedelta(seconds=seconds_ago))

    result = evaluate_enabled_rules(db, evaluation_time)

    assert result["rules_evaluated"] == 0
    assert result["rules_skipped"] == []
    assert result["detections"] == []


def test_invalid_yaml_rule_is_skipped(db):
    evaluation_time = datetime(2026, 10, 23, 12, 0, tzinfo=timezone.utc)

    db.add(
        Rule(
            rule_id="DET-BAD",
            name="Broken Rule",
            description="Invalid YAML test",
            platform="windows",
            definition_yaml="id: [invalid",
            severity="medium",
            enabled=True,
        )
    )
    db.commit()

    result = evaluate_enabled_rules(db, evaluation_time)

    assert result["rules_evaluated"] == 0
    assert result["detections"] == []
    assert result["rules_skipped"] == [
        {"rule_id": "DET-BAD", "reason": "Invalid YAML"}
    ]


def test_events_outside_window_do_not_trigger_detection(db):
    evaluation_time = datetime(2026, 10, 23, 12, 0, tzinfo=timezone.utc)
    make_rule(db, window_seconds=60, count=3)

    # All three events are older than the 60-second detection window.
    for seconds_ago in (90, 80, 70):
        add_event(db, evaluation_time - timedelta(seconds=seconds_ago))

    result = evaluate_enabled_rules(db, evaluation_time)

    assert result["rules_evaluated"] == 1
    assert result["detections"] == []


def test_naive_evaluation_time_is_rejected(db):
    evaluation_time = datetime(2026, 10, 23, 12, 0)

    with pytest.raises(ValueError, match="must include a timezone"):
        evaluate_enabled_rules(db, evaluation_time)

def test_event_exactly_at_window_start_is_excluded(db):
    evaluation_time = datetime(
        2026, 10, 23, 12, 0, tzinfo=timezone.utc
    )
    make_rule(db, window_seconds=60, count=3)

    # The event exactly 60 seconds before evaluation is outside the window.
    for seconds_ago in (60, 30, 10):
        add_event(db, evaluation_time - timedelta(seconds=seconds_ago))

    result = evaluate_enabled_rules(db, evaluation_time)

    assert result["rules_evaluated"] == 1
    assert result["detections"] == []


def test_event_at_evaluation_time_is_included(db):
    evaluation_time = datetime(
        2026, 10, 23, 12, 0, tzinfo=timezone.utc
    )
    make_rule(db, window_seconds=60, count=3)

    for seconds_ago in (30, 10, 0):
        add_event(db, evaluation_time - timedelta(seconds=seconds_ago))

    result = evaluate_enabled_rules(db, evaluation_time)

    assert result["rules_evaluated"] == 1
    assert len(result["detections"]) == 1
    assert result["detections"][0]["count"] == 3