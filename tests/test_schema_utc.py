from datetime import datetime, timedelta, timezone

from pydantic import BaseModel

from app.schemas import RuleCoverageItem, UtcDatetime


class Holder(BaseModel):
    at: UtcDatetime


def test_naive_value_is_marked_as_utc():
    result = Holder(at=datetime(2026, 10, 24, 12, 0)).at

    assert result == datetime(2026, 10, 24, 12, 0, tzinfo=timezone.utc)
    assert result.utcoffset() == timedelta(0)


def test_offset_value_is_converted_to_utc():
    ist = timezone(timedelta(hours=5, minutes=30))

    result = Holder(at=datetime(2026, 10, 24, 12, 0, tzinfo=ist)).at

    assert result == datetime(2026, 10, 24, 6, 30, tzinfo=timezone.utc)


def test_coverage_item_returns_aware_latest_run_time():
    item = RuleCoverageItem(
        rule_id="DET-001",
        rule_name="Multiple Failed Logins",
        enabled=True,
        total_runs=1,
        pass_count=1,
        fail_count=0,
        distinct_scenarios=1,
        latest_status="PASS",
        latest_run_at=datetime(2026, 10, 24, 10, 26, 26),
        coverage_status="TESTED",
    )

    assert item.latest_run_at.utcoffset() == timedelta(0)


def test_coverage_item_allows_missing_latest_run_time():
    item = RuleCoverageItem(
        rule_id="DET-001",
        rule_name="Multiple Failed Logins",
        enabled=True,
        total_runs=0,
        pass_count=0,
        fail_count=0,
        distinct_scenarios=0,
        coverage_status="UNTESTED",
    )

    assert item.latest_run_at is None