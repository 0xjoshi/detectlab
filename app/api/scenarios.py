
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from app.dependencies import get_db
from app.detection.scenario import run_scenario
from app.detection.scenario_library import run_library_scenario
from app.models import ScenarioRun
from app.schemas import (
    ScenarioRunHistoryItem,
    ScenarioRunHistoryResponse,
    ScenarioRunRequest,
)


router = APIRouter(
    prefix="/api/v1/scenarios",
    tags=["scenarios"],
)


@router.post("/run")
def execute_scenario(
    request: ScenarioRunRequest,
    db: Session = Depends(get_db),
):
    return run_scenario(db=db, request=request)


@router.post("/library/{scenario_id}/run")
def execute_library_scenario(
    scenario_id: str,
    db: Session = Depends(get_db),
):
    return run_library_scenario(
        db=db,
        scenario_id=scenario_id,
    )


@router.get(
    "/runs",
    response_model=ScenarioRunHistoryResponse,
)
def list_scenario_runs(
    limit: int = Query(default=20, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
):
    """List scenario run history, newest first."""

    query = db.query(ScenarioRun)
    total = query.count()

    runs = (
        query
        .order_by(ScenarioRun.created_at.desc(), ScenarioRun.id.desc())
        .offset(offset)
        .limit(limit)
        .all()
    )

    return {
        "items": runs,
        "total": total,
        "limit": limit,
        "offset": offset,
    }


@router.get(
    "/runs/{run_id}",
    response_model=ScenarioRunHistoryItem,
)
def get_scenario_run(
    run_id: int,
    db: Session = Depends(get_db),
):
    """Retrieve a single scenario run by its database ID."""

    run = (
        db.query(ScenarioRun)
        .filter(ScenarioRun.id == run_id)
        .first()
    )

    if run is None:
        raise HTTPException(
            status_code=404,
            detail=f"Scenario run {run_id} was not found.",
        )

    return run
