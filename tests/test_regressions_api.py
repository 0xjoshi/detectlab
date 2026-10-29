
from datetime import datetime, timedelta, timezone

import yaml
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.database import Base
from app.dependencies import get_db
from app.main import app
from app.models import Rule, ScenarioRun


@pytest.fixture
def test_db():
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

    def override_get_db():
        db = TestingSessionLocal()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = override_get_db

    with TestingSessionLocal() as db:
        for rule_id in ("DET-001", "DET-002"):
            definition = {
                "id": rule_id,
                "name": f"Rule {rule_id}",
                "description": "Regression test rule",
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
            db.add(
                Rule(
                    rule_id=rule_id,
                    name=f"Rule {rule_id}",
                    description="Regression test rule",
                    platform="windows",
                    definition_yaml=yaml.safe_dump(definition),
                    severity="medium",
                    enabled=True,
                )
            )
        db.commit()

    try:
        yield TestingSessionLocal
    finally:
        app.dependency_overrides.clear()
        Base.metadata.drop_all(bind=engine)
        engine.dispose()


@pytest.fixture
def client(test_db):
    with TestClient(app) as test_client:
        yield test_client


def add_run(db, scenario_id, rule_id, status, created_at):
    db.add(
        ScenarioRun(
            scenario_id=scenario_id,
            scenario_name=scenario_id,
            expected_rule_id=rule_id,
            expected_host="WIN11-LAB",
            evaluation_time=created_at,
            created_at=created_at,
            status=status,
            matched=status == "PASS",
            events_ingested=3,
            event_ids=[],
            detections=[],
        )
    )
    db.commit()


def test_latest_failure_is_reported_as_regression(client, test_db):
    now = datetime(2026, 10, 23, 12, 0, tzinfo=timezone.utc)

    with test_db() as db:
        add_run(db, "SCN-FAIL", "DET-001", "FAIL", now)

    response = client.get("/api/v1/regressions")

    assert response.status_code == 200
    data = response.json()

    assert data["total_rules"] == 2
    assert data["regression_rules"] == 1
    assert data["healthy_rules"] == 0
    assert data["untested_rules"] == 1

    failed_rule = next(
        rule for rule in data["rules"]
        if rule["rule_id"] == "DET-001"
    )
    assert failed_rule["regression_status"] == "REGRESSION"
    assert failed_rule["latest_status"] == "FAIL"
    assert failed_rule["latest_scenario_id"] == "SCN-FAIL"
    assert failed_rule["total_runs"] == 1


def test_later_pass_clears_previous_regression(client, test_db):
    now = datetime(2026, 10, 23, 12, 0, tzinfo=timezone.utc)

    with test_db() as db:
        add_run(db, "SCN-A", "DET-001", "FAIL", now)
        add_run(
            db,
            "SCN-B",
            "DET-001",
            "PASS",
            now + timedelta(minutes=1),
        )

    response = client.get("/api/v1/regressions")
    data = response.json()

    assert response.status_code == 200
    assert data["regression_rules"] == 0
    assert data["healthy_rules"] == 1
    assert data["untested_rules"] == 1

    rule = next(
        item for item in data["rules"]
        if item["rule_id"] == "DET-001"
    )
    assert rule["total_runs"] == 2
    assert rule["latest_status"] == "PASS"
    assert rule["latest_scenario_id"] == "SCN-B"
    assert rule["regression_status"] == "HEALTHY"


def test_rule_without_runs_is_untested(client):
    response = client.get("/api/v1/regressions")

    assert response.status_code == 200
    data = response.json()

    assert data["regression_rules"] == 0
    assert data["healthy_rules"] == 0
    assert data["untested_rules"] == 2

    assert all(
        rule["regression_status"] == "UNTESTED"
        and rule["latest_status"] is None
        for rule in data["rules"]
    )


def test_empty_rule_database_returns_zero_counts(client, test_db):
    with test_db() as db:
        db.query(Rule).delete()
        db.commit()

    response = client.get("/api/v1/regressions")

    assert response.status_code == 200
    assert response.json() == {
        "total_rules": 0,
        "regression_rules": 0,
        "healthy_rules": 0,
        "untested_rules": 0,
        "unknown_rules": 0,
        "rules": [],
    }
def test_unexpected_latest_status_is_unknown(client, test_db):
    now = datetime(2026, 10, 23, 12, 0, tzinfo=timezone.utc)

    with test_db() as db:
        add_run(db, "SCN-UNKNOWN", "DET-001", "UNEXPECTED", now)

    response = client.get("/api/v1/regressions")

    assert response.status_code == 200
    data = response.json()

    rule = next(
        item for item in data["rules"]
        if item["rule_id"] == "DET-001"
    )

    assert rule["latest_status"] == "UNEXPECTED"
    assert rule["regression_status"] == "UNKNOWN"
    assert data["regression_rules"] == 0
    assert data["healthy_rules"] == 0
    assert data["untested_rules"] == 1
    assert data["unknown_rules"] == 1

def test_unexpected_latest_status_is_not_reported_as_healthy(
    client, test_db
):
    now = datetime(2026, 10, 23, 12, 0, tzinfo=timezone.utc)

    with test_db() as db:
        add_run(db, "SCN-UNKNOWN", "DET-001", "UNKNOWN_STATUS", now)

    response = client.get("/api/v1/regressions")

    assert response.status_code == 200
    data = response.json()

    rule = next(
        item for item in data["rules"]
        if item["rule_id"] == "DET-001"
    )

    assert rule["latest_status"] == "UNKNOWN_STATUS"
    assert rule["regression_status"] == "UNKNOWN"
    assert data["regression_rules"] == 0
    assert data["healthy_rules"] == 0
    assert data["untested_rules"] == 1