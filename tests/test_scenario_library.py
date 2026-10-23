from pathlib import Path

import pytest
import yaml
from fastapi import HTTPException
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.database import Base
from app.dependencies import get_db
from app.detection import scenario_library
from app.main import app
from app.models import Event, Host, Rule


@pytest.fixture
def client(tmp_path, monkeypatch):
    scenario_dir = tmp_path / "scenarios"
    scenario_dir.mkdir()

    monkeypatch.setattr(
        scenario_library,
        "SCENARIO_DIRECTORY",
        scenario_dir,
    )

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

    with TestingSessionLocal() as db:
        db.add(
            Host(
                id=1,
                hostname="WIN11-LAB",
                platform="windows",
                ip_address="192.168.56.10",
            )
        )
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


def write_scenario(directory: Path, content: str, filename="SCN-001.yaml"):
    path = directory / filename
    path.write_text(content, encoding="utf-8")
    return path


def valid_scenario():
    return {
        "scenario_id": "SCN-001",
        "name": "Multiple Failed Logins",
        "description": "Test the failed-login threshold",
        "expected_rule_id": "DET-001",
        "expected_host": "WIN11-LAB",
        "events": [
            {
                "seconds_before_evaluation": seconds,
                "event_type": "authentication_failure",
                "event_data": {
                    "user": "scenario-library-user",
                    "status": "failure",
                },
                "raw_event": {"source": "scenario-library-test"},
            }
            for seconds in (50, 40, 30, 20, 10)
        ],
    }


def test_load_scenario_definition_success(client, tmp_path):
    data = valid_scenario()
    write_scenario(
        scenario_library.SCENARIO_DIRECTORY,
        yaml.safe_dump(data),
    )

    response = client.get("/health")
    assert response.status_code == 200

    definition = scenario_library.load_scenario_definition("SCN-001")
    assert definition.scenario_id == "SCN-001"
    assert definition.expected_rule_id == "DET-001"
    assert len(definition.events) == 5


def test_library_endpoint_passes_threshold(client):
    write_scenario(
        scenario_library.SCENARIO_DIRECTORY,
        yaml.safe_dump(valid_scenario()),
    )

    response = client.post("/api/v1/scenarios/library/SCN-001/run")

    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "PASS"
    assert data["matched"] is True
    assert data["scenario_id"] == "SCN-001"
    assert data["scenario_name"] == "Multiple Failed Logins"
    assert data["events_ingested"] == 5
    assert data["detections"][0]["rule_id"] == "DET-001"
    assert data["detections"][0]["count"] == 5


def test_library_endpoint_returns_404_for_missing_scenario(client):
    response = client.post("/api/v1/scenarios/library/SCN-MISSING/run")
    assert response.status_code == 404


@pytest.mark.parametrize("scenario_id", ["..", "../secret", "bad/id", ""])
def test_loader_rejects_invalid_scenario_id(client, scenario_id):
    with pytest.raises(HTTPException) as exc_info:
        scenario_library.load_scenario_definition(scenario_id)

    assert exc_info.value.status_code == 422


def test_loader_rejects_filename_id_mismatch(client):
    data = valid_scenario()
    data["scenario_id"] = "SCN-OTHER"
    write_scenario(
        scenario_library.SCENARIO_DIRECTORY,
        yaml.safe_dump(data),
    )

    with pytest.raises(HTTPException) as exc_info:
        scenario_library.load_scenario_definition("SCN-001")

    assert exc_info.value.status_code == 422


def test_loader_rejects_malformed_yaml(client):
    write_scenario(
        scenario_library.SCENARIO_DIRECTORY,
        "scenario_id: [broken\n",
    )

    with pytest.raises(HTTPException) as exc_info:
        scenario_library.load_scenario_definition("SCN-001")

    assert exc_info.value.status_code == 422


def test_loader_rejects_duplicate_yaml_keys(client):
    write_scenario(
        scenario_library.SCENARIO_DIRECTORY,
        "scenario_id: SCN-001\n"
        "scenario_id: SCN-002\n",
    )

    with pytest.raises(HTTPException) as exc_info:
        scenario_library.load_scenario_definition("SCN-001")

    assert exc_info.value.status_code == 422


def test_loader_rejects_unexpected_fields(client):
    data = valid_scenario()
    data["unexpected"] = "not allowed"
    write_scenario(
        scenario_library.SCENARIO_DIRECTORY,
        yaml.safe_dump(data),
    )

    with pytest.raises(HTTPException) as exc_info:
        scenario_library.load_scenario_definition("SCN-001")

    assert exc_info.value.status_code == 422


def test_loader_rejects_empty_events(client):
    data = valid_scenario()
    data["events"] = []
    write_scenario(
        scenario_library.SCENARIO_DIRECTORY,
        yaml.safe_dump(data),
    )

    with pytest.raises(HTTPException) as exc_info:
        scenario_library.load_scenario_definition("SCN-001")

    assert exc_info.value.status_code == 422
