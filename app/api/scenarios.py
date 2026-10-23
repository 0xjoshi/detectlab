
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.dependencies import get_db
from app.detection.scenario import run_scenario
from app.detection.scenario_library import run_library_scenario
from app.schemas import ScenarioRunRequest


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
