from copy import deepcopy
from datetime import datetime, timedelta, timezone

import pytest

from app.detection.engine import evaluate_threshold

NOW = datetime(2026, 10, 24, 12, 0, tzinfo=timezone.utc)


def make_rule(count=3, window=60, group_by=None):
    return {
        "id": "DET-EDGE",
        "condition": {
            "type": "threshold",
            "event_type": "login_failure",
            "count": count,
            "window_seconds": window,
            "group_by": ["host", "user"] if group_by is None else group_by,
        },
    }


def make_event(seconds_before=1, host="H1", user="alice"):
    return {
        "host": host,
        "timestamp": NOW - timedelta(seconds=seconds_before),
        "event_type": "login_failure",
        "event_data": {"user": user},
    }


def test_event_exactly_at_evaluation_time_is_counted():
    events = [make_event(0), make_event(1), make_event(2)]

    detections = evaluate_threshold(make_rule(), events, NOW)

    assert len(detections) == 1
    assert detections[0]["count"] == 3


def test_more_events_than_threshold_gives_one_detection_with_full_count():
    events = [make_event(i + 1) for i in range(7)]

    detections = evaluate_threshold(make_rule(), events, NOW)

    assert len(detections) == 1
    assert detections[0]["count"] == 7
    assert detections[0]["threshold"] == 3


def test_empty_event_list_returns_no_detections():
    assert evaluate_threshold(make_rule(), [], NOW) == []


def test_unhashable_group_value_is_ignored_without_error():
    events = [make_event(i + 1) for i in range(3)]
    events.append(make_event(4, user=["not", "hashable"]))

    detections = evaluate_threshold(make_rule(), events, NOW)

    assert len(detections) == 1
    assert detections[0]["count"] == 3
    assert detections[0]["group"]["user"] == "alice"


def test_group_values_of_different_types_are_separate_groups():
    events = [make_event(i + 1, user="1") for i in range(3)]
    events += [make_event(i + 5, user=1) for i in range(2)]

    detections = evaluate_threshold(make_rule(), events, NOW)

    assert len(detections) == 1
    assert detections[0]["group"]["user"] == "1"


def test_nested_event_data_group_field_is_supported():
    events = [make_event(i + 1) for i in range(3)]

    detections = evaluate_threshold(
        make_rule(group_by=["host", "event_data.user"]), events, NOW
    )

    assert detections[0]["group"] == {
        "host": "H1",
        "event_data.user": "alice",
    }


def test_evaluation_is_repeatable_and_does_not_modify_events():
    events = [make_event(i + 1) for i in range(4)]
    before = deepcopy(events)

    first = evaluate_threshold(make_rule(), events, NOW)
    second = evaluate_threshold(make_rule(), events, NOW)

    assert first == second
    assert events == before


@pytest.mark.parametrize(
    "overrides",
    [
        {"count": 0},
        {"count": True},
        {"count": "5"},
        {"window": 0},
        {"window": -1},
        {"window": True},
        {"group_by": []},
        {"group_by": ["host", "host"]},
    ],
)
def test_invalid_rule_configuration_is_rejected(overrides):
    with pytest.raises(ValueError):
        evaluate_threshold(make_rule(**overrides), [], NOW)