import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.database import Base
from app.models import Rule
from app.seed_rules import RULES_DIRECTORY, seed_rules

VALID_RULE = """\
id: DET-T01
name: Test Rule
description: Test description
platform: windows
severity: low
condition:
  type: threshold
  event_type: authentication_failure
  count: 3
  window_seconds: 30
  group_by: [host, user]
"""


@pytest.fixture
def db():
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(bind=engine)
    with sessionmaker(bind=engine)() as session:
        yield session
    engine.dispose()


def test_seed_creates_rule_and_is_idempotent(db, tmp_path):
    (tmp_path / "DET-T01.yaml").write_text(VALID_RULE)

    first = seed_rules(db, tmp_path)
    second = seed_rules(db, tmp_path)

    assert first["created"] == ["DET-T01"]
    assert second["created"] == []
    assert second["existing"] == ["DET-T01"]
    assert db.query(Rule).count() == 1


def test_seed_reports_file_name_that_mismatches_rule_id(db, tmp_path):
    (tmp_path / "DET-WRONG.yaml").write_text(VALID_RULE)

    result = seed_rules(db, tmp_path)

    assert result["created"] == []
    assert result["invalid"][0]["file"] == "DET-WRONG.yaml"
    assert db.query(Rule).count() == 0


def test_shipped_rules_are_all_valid_and_seedable(db):
    result = seed_rules(db, RULES_DIRECTORY)

    assert result["invalid"] == []
    assert "DET-001" in result["created"]
    assert db.query(Rule).filter(Rule.rule_id == "DET-001").one().enabled