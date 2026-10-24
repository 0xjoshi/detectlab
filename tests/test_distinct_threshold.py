from datetime import datetime, timedelta, timezone

import pytest

from app.detection.engine import evaluate_threshold
from app.detection.rule_validator import (
    RuleValidationError,
    validate_rule_definition,
)

NOW = datetime(2026, 10, 24, 12, 0, tzinfo=timezone.utc)
IP = "198.51.100.77"


def make_rule(
    count=5,
    window=300,
    group_by=None,
    distinct_field="user",
):
    condition = {
        "type": "threshold",
        "event_type": "authentication_failure",
        "count": count,
        "window_seconds": window,
        "group_by": ["host", "source_ip"] if group_by is None else group_by,
    }
    if distinct_field is not None:
        condition["distinct_field"] = distinct_field
    return {"id": "DET-DISTINCT", "condition": condition}


def make_event(user, seconds_before=10, ip=IP, host="H1"):
    return {
        "host": host,
        "timestamp": NOW - timedelta(seconds=seconds_before),
        "event_type": "authentication_failure",
        "event_data": {"user": user, "source_ip": ip},
    }


def spray(users, ip=IP, start=10):
    return [
        make_event(user, seconds_before=start + index, ip=ip)
        for index, user in enumerate(users)
    ]


def test_four_distinct_users_do_not_trigger():
    events = spray(["a", "b", "c", "d"])

    assert evaluate_threshold(make_rule(), events, NOW) == []


def test_five_distinct_users_trigger_once():
    events = spray(["a", "b", "c", "d", "e"])

    detections = evaluate_threshold(make_rule(), events, NOW)

    assert len(detections) == 1
    assert detections[0]["count"] == 5
    assert detections[0]["distinct_field"] == "user"
    assert detections[0]["group"] == {"host": "H1", "source_ip": IP}


def test_repeated_attempts_on_one_account_do_not_count_as_spraying():
    events = spray(["alice"] * 20)

    assert evaluate_threshold(make_rule(), events, NOW) == []


def test_more_distinct_users_than_threshold_reports_full_count():
    events = spray(["a", "b", "c", "d", "e", "f", "g"])

    detections = evaluate_threshold(make_rule(), events, NOW)

    assert len(detections) == 1
    assert detections[0]["count"] == 7


def test_event_count_includes_repeated_attempts():
    events = spray(["a", "b", "c", "d", "e"]) + spray(
        ["a", "b", "c", "d", "e"], start=20
    )

    detection = evaluate_threshold(make_rule(), events, NOW)[0]

    assert detection["count"] == 5
    assert detection["event_count"] == 10


def test_distinct_users_from_different_sources_are_not_combined():
    events = spray(["a", "b", "c"], ip="198.51.100.1") + spray(
        ["d", "e", "f"], ip="198.51.100.2"
    )

    assert evaluate_threshold(make_rule(), events, NOW) == []


def test_events_missing_the_distinct_field_are_ignored():
    events = spray(["a", "b", "c", "d"])
    for _ in range(3):
        event = make_event("x")
        del event["event_data"]["user"]
        events.append(event)

    assert evaluate_threshold(make_rule(), events, NOW) == []


def test_unhashable_distinct_values_are_ignored_without_error():
    events = spray(["a", "b", "c", "d"])
    events.append(make_event(["not", "hashable"]))

    assert evaluate_threshold(make_rule(), events, NOW) == []


def test_distinct_values_of_different_types_are_distinct():
    events = spray(["1", 1, "a", "b", "c"])

    detections = evaluate_threshold(make_rule(), events, NOW)

    assert len(detections) == 1
    assert detections[0]["count"] == 5


def test_events_outside_the_window_do_not_count():
    events = spray(["a", "b", "c", "d"])
    events.append(make_event("e", seconds_before=301))

    assert evaluate_threshold(make_rule(), events, NOW) == []


def test_rules_without_distinct_field_keep_their_original_output():
    rule = make_rule(count=3, window=60, distinct_field=None)
    rule["condition"]["group_by"] = ["host", "source_ip"]
    events = spray(["a", "a", "a"])

    detection = evaluate_threshold(rule, events, NOW)[0]

    assert set(detection) == {
        "rule_id",
        "count",
        "threshold",
        "window_seconds",
        "window_start",
        "window_end",
        "group",
    }
    assert detection["count"] == 3


@pytest.mark.parametrize("bad_value", ["", "   ", 5, ["user"]])
def test_invalid_distinct_field_is_rejected_by_the_engine(bad_value):
    with pytest.raises(ValueError, match="distinct_field"):
        evaluate_threshold(make_rule(distinct_field=bad_value), [], NOW)


def test_distinct_field_may_not_also_be_a_group_by_field():
    rule = make_rule(group_by=["host", "user"])

    with pytest.raises(ValueError, match="distinct_field"):
        evaluate_threshold(rule, [], NOW)


VALID_YAML = """\
id: DET-X
name: X
description: X
platform: windows
severity: medium
condition:
  type: threshold
  event_type: authentication_failure
  count: 5
  window_seconds: 300
  distinct_field: user
  group_by: [host, source_ip]
"""


def test_validator_accepts_distinct_field():
    definition = validate_rule_definition(VALID_YAML, "DET-X")

    assert definition["condition"]["distinct_field"] == "user"


def test_validator_rejects_distinct_field_in_group_by():
    text = VALID_YAML.replace(
        "group_by: [host, source_ip]", "group_by: [host, user]"
    )

    with pytest.raises(RuleValidationError, match="distinct_field"):
        validate_rule_definition(text, "DET-X")


def test_validator_rejects_blank_distinct_field():
    text = VALID_YAML.replace("distinct_field: user", 'distinct_field: ""')

    with pytest.raises(RuleValidationError, match="distinct_field"):
        validate_rule_definition(text, "DET-X")