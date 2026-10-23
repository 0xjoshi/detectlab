from datetime import datetime, timedelta, timezone
from statistics import median
from time import perf_counter

import yaml
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.database import Base
from app.detection.service import evaluate_enabled_rules
from app.models import Event, Host, Rule


EVENT_COUNTS = [1_000, 5_000, 10_000]
RULE_COUNT = 5
REPEATS = 5
RECENT_RATIO = 0.80


def seed_rules(db):
    for index in range(RULE_COUNT):
        rule_id = f"DET-BENCH-{index + 1:03}"
        definition = {
            "id": rule_id,
            "name": f"Benchmark Rule {index + 1}",
            "description": "Performance benchmark rule",
            "platform": "windows",
            "severity": "medium",
            "condition": {
                "type": "threshold",
                "event_type": "authentication_failure",
                "count": 5,
                "window_seconds": 60,
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
                enabled=True,
            )
        )

    db.commit()


def seed_events(db, event_count, profile, evaluation_time):
    db.query(Event).delete()
    db.commit()

    if profile == "historical-heavy":
        recent_count = min(5, event_count)
    else:
        recent_count = int(event_count * RECENT_RATIO)

    batch = []

    for index in range(event_count):
        if index < recent_count:
            timestamp = evaluation_time - timedelta(
                seconds=1 + index % 59
            )
            event_type = "authentication_failure"
            user = "benchmark-user"
        else:
            timestamp = evaluation_time - timedelta(
                minutes=10, seconds=index % 60
            )
            event_type = "process_start"
            user = f"user-{index % 100}"

        batch.append(
            Event(
                host_id=1,
                timestamp=timestamp,
                event_type=event_type,
                event_data={"user": user},
                raw_event={"benchmark_index": index},
            )
        )

        if len(batch) >= 1_000:
            db.add_all(batch)
            db.flush()
            batch.clear()

    if batch:
        db.add_all(batch)

    db.commit()
    return recent_count


def measure(db, evaluation_time):
    result = evaluate_enabled_rules(db, evaluation_time)

    assert result["rules_evaluated"] == RULE_COUNT
    assert len(result["detections"]) == RULE_COUNT

    measurements = []

    # Warm up before collecting timings.
    for _ in range(REPEATS):
        started = perf_counter()
        result = evaluate_enabled_rules(db, evaluation_time)
        measurements.append(perf_counter() - started)

        assert result["rules_evaluated"] == RULE_COUNT
        assert len(result["detections"]) == RULE_COUNT

    return median(measurements)


def main():
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    session_factory = sessionmaker(bind=engine)
    Base.metadata.create_all(bind=engine)
    db = session_factory()

    evaluation_time = datetime(
        2026, 10, 23, 12, 0, tzinfo=timezone.utc
    )

    try:
        db.add(
            Host(
                id=1,
                hostname="WIN11-LAB",
                platform="windows",
                ip_address="192.168.56.10",
            )
        )
        db.commit()
        seed_rules(db)

        print("DetectLab detection service benchmark")
        print(f"Enabled rules: {RULE_COUNT}")
        print(f"Measurements per workload: {REPEATS}")
        print("Times are median wall-clock seconds.")
        print()

        for profile in ("historical-heavy", "recent-heavy"):
            print(f"Workload: {profile}")
            print(
                f"{'Events':>10} {'Recent':>10} "
                f"{'Median (s)':>14} {'Events/s':>14}"
            )

            for event_count in EVENT_COUNTS:
                recent_count = seed_events(
                    db,
                    event_count,
                    profile,
                    evaluation_time,
                )
                elapsed = measure(db, evaluation_time)
                throughput = (
                    event_count / elapsed if elapsed else float("inf")
                )

                print(
                    f"{event_count:>10,} {recent_count:>10,} "
                    f"{elapsed:>14.6f} {throughput:>14,.0f}"
                )

            print()

    finally:
        db.close()
        Base.metadata.drop_all(bind=engine)
        engine.dispose()


if __name__ == "__main__":
    main()