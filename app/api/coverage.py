
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.dependencies import get_db
from app.models import Rule, ScenarioRun
from app.schemas import (
    DetectionCoverageResponse,
    RuleCoverageItem,
)


router = APIRouter(
    prefix="/api/v1/coverage",
    tags=["coverage"],
)


@router.get(
    "",
    response_model=DetectionCoverageResponse,
)
def get_detection_coverage(
    db: Session = Depends(get_db),
):
    """Summarize scenario test coverage for every detection rule."""

    rules = db.query(Rule).order_by(Rule.rule_id).all()
    runs = (
        db.query(ScenarioRun)
        .order_by(ScenarioRun.created_at.desc(), ScenarioRun.id.desc())
        .all()
    )

    runs_by_rule: dict[str, list[ScenarioRun]] = {}
    for run in runs:
        runs_by_rule.setdefault(run.expected_rule_id, []).append(run)

    items = []

    for rule in rules:
        rule_runs = runs_by_rule.get(rule.rule_id, [])
        pass_count = sum(run.status == "PASS" for run in rule_runs)
        fail_count = sum(run.status == "FAIL" for run in rule_runs)

        # Runs are newest first; use the first one for the latest result.
        latest_run = rule_runs[0] if rule_runs else None

        items.append(
            RuleCoverageItem(
                rule_id=rule.rule_id,
                rule_name=rule.name,
                enabled=rule.enabled,
                total_runs=len(rule_runs),
                pass_count=pass_count,
                fail_count=fail_count,
                distinct_scenarios=len(
                    {run.scenario_id for run in rule_runs}
                ),
                latest_status=latest_run.status if latest_run else None,
                latest_run_at=latest_run.created_at if latest_run else None,
                coverage_status="TESTED" if rule_runs else "UNTESTED",
            )
        )

    total_rules = len(items)
    tested_rules = sum(item.total_runs > 0 for item in items)
    untested_rules = total_rules - tested_rules
    coverage_percent = (
        round(tested_rules / total_rules * 100, 2)
        if total_rules
        else 0.0
    )

    return DetectionCoverageResponse(
        total_rules=total_rules,
        tested_rules=tested_rules,
        untested_rules=untested_rules,
        coverage_percent=coverage_percent,
        rules=items,
    )