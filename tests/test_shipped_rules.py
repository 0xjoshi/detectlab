from datetime import datetime, timedelta, timezone

import pytest
import yaml
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.database import Base
from app.detection import scenario_library
from app.detection.engine import evaluate_threshold
from app.detection.scenario_library import run_library_scenario
from app.models import Host
from app.seed_rules import RULES_DIRECTORY, seed_rules

SCENARIO_IDS = sorted(
    path.stem for path in scenario_library.SCENARIO_DIRECTORY.glob("*.yaml")
)


@pytest.fixture
def db():
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(bind=engine)

    with sessionmaker(bind=engine)() as session:
        session.add_all(
            [
                Host(hostname="WIN11-LAB", platform="windows"),
                Host(hostname="UBUNTU-LAB", platform="linux"),
            ]
        )
        session.commit()
        seed_rules(session, RULES_DIRECTORY)
        yield session

    engine.dispose()


@pytest.mark.parametrize("scenario_id", SCENARIO_IDS)
def test_every_shipped_scenario_passes_against_shipped_rules(db, scenario_id):
    result = run_library_scenario(db, scenario_id)

    assert result["status"] == "PASS"
    assert result["matched"] is result["expected_detection"]


def det_002():
    return yaml.safe_load((RULES_DIRECTORY / "DET-002.yaml").read_text())


def ssh_events(source_ip, count, now):
    return [
        {
            "host": "UBUNTU-LAB",
            "timestamp": now - timedelta(seconds=1 + index),
            "event_type": "ssh_authentication_failure",
            "event_data": {"source_ip": source_ip},
        }
        for index in range(count)
    ]


NOW = datetime(2026, 10, 24, 12, 0, tzinfo=timezone.utc)


def test_det_002_triggers_at_ten_failures_from_one_source():
    detections = evaluate_threshold(
        det_002(), ssh_events("203.0.113.50", 10, NOW), NOW
    )

    assert len(detections) == 1
    assert detections[0]["group"] == {
        "host": "UBUNTU-LAB",
        "source_ip": "203.0.113.50",
    }


def test_det_002_does_not_trigger_below_threshold():
    assert evaluate_threshold(
        det_002(), ssh_events("203.0.113.50", 9, NOW), NOW
    ) == []


def test_det_002_does_not_combine_failures_from_different_sources():
    events = (
        ssh_events("203.0.113.50", 5, NOW)
        + ssh_events("203.0.113.51", 5, NOW)
    )

    assert evaluate_threshold(det_002(), events, NOW) == []