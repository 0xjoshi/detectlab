from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.dependencies import get_db
from app.models import Rule, ScenarioRun
from app.schemas import (
    RegressionReportResponse,
    RuleRegressionItem,
)


router = APIRouter(
    prefix="/api/v1/regressions",
    tags=["regressions"],
)


@router.get("", response_model=RegressionReportResponse)
def get_regression_report(
    db: Session = Depends(get_db),
):
    """Report the latest scenario validation status for every rule."""

    rules = db.query(Rule).order_by(Rule.rule_id).all()

    runs = (
        db.query(ScenarioRun)
        .order_by(
            ScenarioRun.created_at.desc(),
            ScenarioRun.id.desc(),
        )
        .all()
    )

    runs_by_rule: dict[str, list[ScenarioRun]] = {}

    for run in runs:
        runs_by_rule.setdefault(
            run.expected_rule_id, []
        ).append(run)

    items = []

    for rule in rules:
        rule_runs = runs_by_rule.get(rule.rule_id, [])
        latest_run = rule_runs[0] if rule_runs else None

        if latest_run is None:
            status = "UNTESTED"
        elif latest_run.status == "FAIL":
            status = "REGRESSION"
        elif latest_run.status == "PASS":
            status = "HEALTHY"
        else:
            status = "UNKNOWN"

        items.append(
            RuleRegressionItem(
                rule_id=rule.rule_id,
                rule_name=rule.name,
                enabled=rule.enabled,
                total_runs=len(rule_runs),
                latest_status=(
                    latest_run.status if latest_run else None
                ),
                latest_run_at=(
                    latest_run.created_at if latest_run else None
                ),
                latest_scenario_id=(
                    latest_run.scenario_id if latest_run else None
                ),
                regression_status=status,
            )
        )

    return RegressionReportResponse(
        total_rules=len(items),
        regression_rules=sum(
            item.regression_status == "REGRESSION"
            for item in items
        ),
        healthy_rules=sum(
            item.regression_status == "HEALTHY"
            for item in items
        ),
        untested_rules=sum(
            item.regression_status == "UNTESTED"
            for item in items
        ),
        unknown_rules=sum(
            item.regression_status == "UNKNOWN"
            for item in items
        ),
        rules=items,
    )
