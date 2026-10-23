
from datetime import datetime, timezone

from sqlalchemy import Boolean, DateTime, ForeignKey, JSON, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base


class Host(Base):
    __tablename__ = "hosts"

    id: Mapped[int] = mapped_column(primary_key=True)
    hostname: Mapped[str] = mapped_column(
        String(255), unique=True, nullable=False
    )
    platform: Mapped[str] = mapped_column(String(50), nullable=False)
    ip_address: Mapped[str | None] = mapped_column(String(45), nullable=True)


class Rule(Base):
    __tablename__ = "rules"

    id: Mapped[int] = mapped_column(primary_key=True)
    rule_id: Mapped[str] = mapped_column(
        String(100), unique=True, index=True, nullable=False
    )
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    platform: Mapped[str] = mapped_column(String(50), nullable=False)
    definition_yaml: Mapped[str] = mapped_column(Text, nullable=False)
    severity: Mapped[str] = mapped_column(String(50), nullable=False)
    mitre_technique: Mapped[str | None] = mapped_column(
        String(50), nullable=True
    )
    enabled: Mapped[bool] = mapped_column(
        Boolean, default=True, nullable=False
    )


class Event(Base):
    __tablename__ = "events"

    id: Mapped[int] = mapped_column(primary_key=True)

    host_id: Mapped[int] = mapped_column(
        ForeignKey("hosts.id"), nullable=False, index=True
    )

    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, index=True
    )

    event_type: Mapped[str] = mapped_column(
        String(100), nullable=False, index=True
    )

    event_data: Mapped[dict] = mapped_column(JSON, nullable=False)

    raw_event: Mapped[dict] = mapped_column(JSON, nullable=False)


class ScenarioRun(Base):
    __tablename__ = "scenario_runs"

    id: Mapped[int] = mapped_column(primary_key=True)

    scenario_id: Mapped[str] = mapped_column(
        String(100), nullable=False, index=True
    )
    scenario_name: Mapped[str | None] = mapped_column(
        String(255), nullable=True
    )
    expected_rule_id: Mapped[str] = mapped_column(
        String(100), nullable=False, index=True
    )
    expected_host: Mapped[str] = mapped_column(
        String(255), nullable=False, index=True
    )

    evaluation_time: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, index=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    status: Mapped[str] = mapped_column(String(20), nullable=False)
    matched: Mapped[bool] = mapped_column(Boolean, nullable=False)
    events_ingested: Mapped[int] = mapped_column(nullable=False)

    event_ids: Mapped[list] = mapped_column(JSON, nullable=False)
    detections: Mapped[list] = mapped_column(JSON, nullable=False)
