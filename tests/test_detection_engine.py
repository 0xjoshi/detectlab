import pytest
from datetime import datetime, timedelta, timezone

from app.detection.engine import evaluate_threshold


def make_event(
    timestamp,
    user="labuser",
    host="WIN11-LAB",
    event_type="authentication_failure",
):
    return {
        "timestamp": timestamp,
        "event_type": event_type,
        "event_data": {
            "user": user,
        },
        "host": host,
    }


def make_rule(
    count=3,
    window_seconds=60,
    group_by=None,
    event_type="authentication_failure",
):
    return {
        "id": "DET-001",
        "condition": {
            "type": "threshold",
            "event_type": event_type,
            "count": count,
            "window_seconds": window_seconds,
            "group_by": group_by or ["host", "user"],
        },
    }


def test_threshold_triggers_at_configured_count():
    now = datetime(2026, 10, 21, 5, 30, tzinfo=timezone.utc)
    events = [
        make_event(now - timedelta(seconds=20)),
        make_event(now - timedelta(seconds=10)),
        make_event(now),
    ]

    result = evaluate_threshold(make_rule(count=3), events, now)

    assert len(result) == 1
    assert result[0]["rule_id"] == "DET-001"
    assert result[0]["count"] == 3


def test_threshold_does_not_trigger_below_count():
    now = datetime(2026, 10, 21, 5, 30, tzinfo=timezone.utc)
    events = [
        make_event(now - timedelta(seconds=20)),
        make_event(now - timedelta(seconds=10)),
    ]

    result = evaluate_threshold(make_rule(count=3), events, now)

    assert result == []


def test_events_outside_window_are_excluded():
    now = datetime(2026, 10, 21, 5, 30, tzinfo=timezone.utc)
    events = [
        make_event(now - timedelta(seconds=61)),
        make_event(now - timedelta(seconds=30)),
        make_event(now - timedelta(seconds=10)),
    ]

    result = evaluate_threshold(make_rule(count=3), events, now)

    assert result == []


def test_different_users_are_separate_groups():
    now = datetime(2026, 10, 21, 5, 30, tzinfo=timezone.utc)
    events = [
        make_event(now - timedelta(seconds=20), user="alice"),
        make_event(now - timedelta(seconds=10), user="bob"),
        make_event(now, user="alice"),
    ]

    result = evaluate_threshold(make_rule(count=2), events, now)

    assert len(result) == 1
    assert result[0]["group"]["user"] == "alice"
    assert result[0]["count"] == 2


def test_different_event_types_are_not_counted():
    now = datetime(2026, 10, 21, 5, 30, tzinfo=timezone.utc)
    events = [
        make_event(now - timedelta(seconds=20)),
        make_event(
            now - timedelta(seconds=10),
            event_type="process_created",
        ),
        make_event(now),
    ]

    result = evaluate_threshold(make_rule(count=3), events, now)

    assert result == []


def test_future_events_are_excluded():
    now = datetime(2026, 10, 21, 5, 30, tzinfo=timezone.utc)
    events = [
        make_event(now - timedelta(seconds=10)),
        make_event(now + timedelta(seconds=5)),
        make_event(now + timedelta(seconds=10)),
    ]

    result = evaluate_threshold(make_rule(count=3), events, now)

    assert result == []
def test_event_exactly_at_window_start_is_excluded():
    now = datetime(2026, 10, 21, 5, 30, tzinfo=timezone.utc)
    events = [
        make_event(now - timedelta(seconds=60)),
        make_event(now - timedelta(seconds=30)),
        make_event(now),
    ]

    result = evaluate_threshold(make_rule(count=3), events, now)

    assert result == []

def test_missing_group_field_does_not_trigger_detection():
    now = datetime(2026, 10, 21, 5, 30, tzinfo=timezone.utc)
    events = [
        {
            "timestamp": now - timedelta(seconds=20),
            "event_type": "authentication_failure",
            "event_data": {},
            "host": "WIN11-LAB",
        },
        {
            "timestamp": now - timedelta(seconds=10),
            "event_type": "authentication_failure",
            "event_data": {},
            "host": "WIN11-LAB",
        },
    ]

    result = evaluate_threshold(make_rule(count=2), events, now)

    assert result == []


def test_detection_results_are_separate_per_host():
    now = datetime(2026, 10, 21, 5, 30, tzinfo=timezone.utc)
    events = [
        make_event(now - timedelta(seconds=20), host="WIN11-LAB"),
        make_event(now - timedelta(seconds=10), host="WIN11-LAB"),
        make_event(now - timedelta(seconds=20), host="UBUNTU-LAB"),
        make_event(now - timedelta(seconds=10), host="UBUNTU-LAB"),
    ]

    result = evaluate_threshold(make_rule(count=2), events, now)

    assert len(result) == 2
    assert {item["group"]["host"] for item in result} == {
        "WIN11-LAB",
        "UBUNTU-LAB",
    }
def test_rejects_non_threshold_rule():
    rule = make_rule()
    rule["condition"]["type"] = "keyword"

    with pytest.raises(ValueError, match="threshold"):
        evaluate_threshold(
            rule,
            [],
            datetime(2026, 10, 21, 5, 30, tzinfo=timezone.utc),
        )


def test_rejects_missing_threshold_configuration():
    rule = make_rule()
    del rule["condition"]["count"]

    with pytest.raises(ValueError, match="count"):
        evaluate_threshold(
            rule,
            [],
            datetime(2026, 10, 21, 5, 30, tzinfo=timezone.utc),
        )


def test_rejects_naive_evaluation_time():
    rule = make_rule()

    with pytest.raises(ValueError, match="timezone-aware"):
        evaluate_threshold(
            rule,
            [],
            datetime(2026, 10, 21, 5, 30),
        )
def test_event_with_string_timestamp_is_ignored():
    now = datetime(2026, 10, 21, 5, 30, tzinfo=timezone.utc)
    events = [
        make_event("2026-10-21T05:29:50Z"),
        make_event(now - timedelta(seconds=10)),
        make_event(now),
    ]

    result = evaluate_threshold(make_rule(count=2), events, now)

    assert len(result) == 1
    assert result[0]["count"] == 2


def test_event_with_naive_timestamp_is_ignored():
    now = datetime(2026, 10, 21, 5, 30, tzinfo=timezone.utc)
    events = [
        make_event(datetime(2026, 10, 21, 5, 29, 50)),
        make_event(now - timedelta(seconds=10)),
        make_event(now),
    ]

    result = evaluate_threshold(make_rule(count=2), events, now)

    assert len(result) == 1
    assert result[0]["count"] == 2

def test_timezone_offset_timestamp_is_normalized_to_utc():
    now = datetime(2026, 10, 21, 5, 30, tzinfo=timezone.utc)

    # 10:59:50 at UTC+05:30 is 05:29:50 UTC.
    offset_timestamp = datetime(
        2026,
        10,
        21,
        10,
        59,
        50,
        tzinfo=timezone(timedelta(hours=5, minutes=30)),
    )

    events = [
        make_event(offset_timestamp),
        make_event(now - timedelta(seconds=20)),
        make_event(now),
    ]

    result = evaluate_threshold(make_rule(count=3), events, now)

    assert len(result) == 1
    assert result[0]["count"] == 3
