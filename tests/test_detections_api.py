import pytest
from datetime import datetime, timedelta, timezone

import yaml
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.database import Base
from app.dependencies import get_db
from app.main import app
from app.models import Event, Host, Rule


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

        rule_definition = {
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
                definition_yaml=yaml.safe_dump(rule_definition),
                severity="medium",
                enabled=True,
            )
        )

        now = datetime(2026, 10, 21, 5, 30, tzinfo=timezone.utc)
        for seconds_ago in (20, 10, 0):
            db.add(
                Event(
                    host_id=1,
                    timestamp=now - timedelta(seconds=seconds_ago),
                    event_type="authentication_failure",
                    event_data={"user": "labuser"},
                    raw_event={"event_id": 4625},
                )
            )

        db.commit()

    with TestClient(app) as test_client:
        yield test_client

    app.dependency_overrides.clear()
    Base.metadata.drop_all(bind=engine)
    engine.dispose()


def test_evaluate_endpoint_detects_threshold(client):
    response = client.post(
        "/api/v1/detections/evaluate",
        json={"evaluation_time": "2026-10-21T05:30:00Z"},
    )

    assert response.status_code == 200
    data = response.json()
    assert len(data["detections"]) == 1
    assert data["detections"][0]["rule_id"] == "DET-001"
    assert data["detections"][0]["count"] == 3
    assert data["detections"][0]["group"]["host"] == "WIN11-LAB"
    assert data["detections"][0]["group"]["user"] == "labuser"


def test_evaluate_endpoint_rejects_naive_evaluation_time(client):
    response = client.post(
        "/api/v1/detections/evaluate",
        json={"evaluation_time": "2026-10-21T05:30:00"},
    )

    assert response.status_code == 422


def test_evaluate_endpoint_does_not_persist_results(client):
    client.post(
        "/api/v1/detections/evaluate",
        json={"evaluation_time": "2026-10-21T05:30:00Z"},
    )

    response = client.post(
        "/api/v1/detections/evaluate",
        json={"evaluation_time": "2026-10-21T05:30:00Z"},
    )

    assert response.status_code == 200
    assert len(response.json()["detections"]) == 1

def test_validate_endpoint_returns_pass_when_rule_and_host_match(client):
    response = client.post(
        "/api/v1/detections/validate",
        json={
            "evaluation_time": "2026-10-21T05:30:00Z",
            "expected_rule_id": "DET-001",
            "expected_host": "WIN11-LAB",
        },
    )

    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "PASS"
    assert data["matched"] is True
    assert data["expected_rule_id"] == "DET-001"
    assert data["expected_host"] == "WIN11-LAB"
    assert len(data["detections"]) == 1
    assert data["detections"][0]["count"] == 3


def test_validate_endpoint_returns_fail_when_rule_does_not_match(client):
    response = client.post(
        "/api/v1/detections/validate",
        json={
            "evaluation_time": "2026-10-21T05:30:00Z",
            "expected_rule_id": "DET-999",
            "expected_host": "WIN11-LAB",
        },
    )

    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "FAIL"
    assert data["matched"] is False
    assert data["expected_rule_id"] == "DET-999"


def test_validate_endpoint_rejects_naive_evaluation_time(client):
    response = client.post(
        "/api/v1/detections/validate",
        json={
            "evaluation_time": "2026-10-21T05:30:00",
            "expected_rule_id": "DET-001",
            "expected_host": "WIN11-LAB",
        },
    )

    assert response.status_code == 422