
from datetime import datetime, timedelta, timezone

import pytest
import yaml
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.database import Base
from app.dependencies import get_db
from app.main import app
from app.models import Host, Rule


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
        db.add(
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
        db.add(
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
        db.commit()

    with TestClient(app) as test_client:
        yield test_client

    app.dependency_overrides.clear()
    Base.metadata.drop_all(bind=engine)
    engine.dispose()


def make_payload(event_count=3):
    evaluation_time = datetime(
        2026, 10, 22, 16, 0, tzinfo=timezone.utc
    )
    events = [
        {
            "timestamp": (
                evaluation_time - timedelta(seconds=10 * (event_count - i))
            ).isoformat(),
            "event_type": "authentication_failure",
            "event_data": {
                "user": "scenario-api-user",
                "status": "failure",
            },
            "raw_event": {"source": "scenario-api-test"},
        }
        for i in range(event_count)
    ]
    return {
        "scenario_id": "SCN-API-001",
        "expected_rule_id": "DET-001",
        "expected_host": "WIN11-LAB",
        "evaluation_time": evaluation_time.isoformat(),
        "events": events,
    }


def test_run_scenario_endpoint_passes(client):
    response = client.post(
        "/api/v1/scenarios/run",
        json=make_payload(),
    )

    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "PASS"
    assert data["matched"] is True
    assert data["scenario_id"] == "SCN-API-001"
    assert data["events_ingested"] == 3
    assert len(data["event_ids"]) == 3
    assert data["detections"][0]["rule_id"] == "DET-001"
    assert data["detections"][0]["count"] == 3


def test_run_scenario_endpoint_fails_below_threshold(client):
    response = client.post(
        "/api/v1/scenarios/run",
        json=make_payload(event_count=2),
    )

    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "FAIL"
    assert data["matched"] is False
    assert data["detections"] == []


def test_run_scenario_endpoint_rejects_naive_evaluation_time(client):
    payload = make_payload()
    payload["evaluation_time"] = "2026-10-22T16:00:00"

    response = client.post(
        "/api/v1/scenarios/run",
        json=payload,
    )

    assert response.status_code == 422


def test_run_scenario_endpoint_rejects_naive_event_timestamp(client):
    payload = make_payload()
    payload["events"][0]["timestamp"] = "2026-10-22T15:59:50"

    response = client.post(
        "/api/v1/scenarios/run",
        json=payload,
    )

    assert response.status_code == 422


def test_run_scenario_endpoint_returns_404_for_unknown_host(client):
    payload = make_payload()
    payload["expected_host"] = "UNKNOWN-HOST"

    response = client.post(
        "/api/v1/scenarios/run",
        json=payload,
    )

    assert response.status_code == 404
