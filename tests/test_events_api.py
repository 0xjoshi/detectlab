from datetime import datetime, timezone

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.database import Base
from app.dependencies import get_db
from app.main import app
from app.models import Host


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
                hostname="TEST-WIN",
                platform="windows",
                ip_address="192.168.1.10",
            )
        )
        db.commit()

    with TestClient(app) as test_client:
        yield test_client

    app.dependency_overrides.clear()
    Base.metadata.drop_all(bind=engine)
    engine.dispose()


def valid_event_payload():
    return {
        "host_id": 1,
        "timestamp": datetime(
            2026, 10, 21, 5, 30, tzinfo=timezone.utc
        ).isoformat(),
        "event_type": "authentication_failure",
        "event_data": {
            "user": "labuser",
            "status": "failure",
        },
        "raw_event": {
            "event_id": 4625,
            "message": "An account failed to log on",
        },
    }


def test_create_event_returns_created_event(client):
    response = client.post(
        "/api/v1/events",
        json=valid_event_payload(),
    )

    assert response.status_code == 201
    data = response.json()
    assert data["id"] == 1
    assert data["host_id"] == 1
    assert data["event_type"] == "authentication_failure"
    assert data["event_data"]["user"] == "labuser"


def test_create_event_rejects_unknown_host(client):
    payload = valid_event_payload()
    payload["host_id"] = 9999

    response = client.post("/api/v1/events", json=payload)

    assert response.status_code == 404


def test_list_events_returns_persisted_event(client):
    payload = valid_event_payload()
    create_response = client.post("/api/v1/events", json=payload)

    assert create_response.status_code == 201

    response = client.get("/api/v1/events")

    assert response.status_code == 200
    data = response.json()
    assert len(data) == 1
    assert data[0]["event_type"] == "authentication_failure"


def test_create_event_rejects_invalid_payload(client):
    payload = valid_event_payload()
    payload.pop("event_type")

    response = client.post("/api/v1/events", json=payload)

    assert response.status_code == 422