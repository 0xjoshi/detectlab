
from datetime import datetime, timezone

import yaml
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.database import Base
from app.dependencies import get_db
from app.main import app
from app.models import Host, Rule, ScenarioRun


@pytest.fixture
def client():
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
                "description": "Coverage test rule",
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
                    description="Coverage test rule",
                    platform="windows",
                    definition_yaml=yaml.safe_dump(definition),
                    severity="medium",
                    enabled=True,
                )
            )
        db.commit()

    with TestClient(app) as test_client:
        yield test_client

    app.dependency_overrides.clear()
    Base.metadata.drop_all(bind=engine)
    engine.dispose()


def add_run(
    db,
    scenario_id: str,
    rule_id: str,
    status: str,
    created_at: datetime,
):
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


def test_coverage_reports_all_rules_as_untested(client):
    response = client.get("/api/v1/coverage")

    assert response.status_code == 200
    data = response.json()

    assert data["total_rules"] == 2
    assert data["tested_rules"] == 0
    assert data["untested_rules"] == 2
    assert data["coverage_percent"] == 0.0
    assert all(
        rule["coverage_status"] == "UNTESTED"
        for rule in data["rules"]
    )


def test_coverage_aggregates_pass_fail_and_distinct_scenarios(client):
    with next(
        app.dependency_overrides[get_db]()
    ) as db:
        now = datetime(2026, 10, 23, 12, 0, tzinfo=timezone.utc)

        add_run(db, "SCN-A", "DET-001", "PASS", now)
        add_run(
            db,
            "SCN-A",
            "DET-001",
            "FAIL",
            now.replace(minute=1),
        )
        add_run(
            db,
            "SCN-B",
            "DET-001",
            "PASS",
            now.replace(minute=2),
        )

    response = client.get("/api/v1/coverage")

    assert response.status_code == 200
    data = response.json()

    assert data["total_rules"] == 2
    assert data["tested_rules"] == 1
    assert data["untested_rules"] == 1
    assert data["coverage_percent"] == 50.0

    rule = next(item for item in data["rules"] if item["rule_id"] == "DET-001")
    assert rule["total_runs"] == 3
    assert rule["pass_count"] == 2
    assert rule["fail_count"] == 1
    assert rule["distinct_scenarios"] == 2
    assert rule["latest_status"] == "PASS"
    assert rule["coverage_status"] == "TESTED"

    untested = next(
        item for item in data["rules"] if item["rule_id"] == "DET-002"
    )
    assert untested["total_runs"] == 0
    assert untested["latest_status"] is None
    assert untested["coverage_status"] == "UNTESTED"


def test_coverage_returns_zero_percent_when_no_rules_exist(client):
    # This fixture starts with two rules, so delete them for this test.
    with next(
        app.dependency_overrides[get_db]()
    ) as db:
        db.query(Rule).delete()
        db.commit()

    response = client.get("/api/v1/coverage")

    assert response.status_code == 200
    assert response.json() == {
        "total_rules": 0,
        "tested_rules": 0,
        "untested_rules": 0,
        "coverage_percent": 0.0,
        "rules": [],
    }