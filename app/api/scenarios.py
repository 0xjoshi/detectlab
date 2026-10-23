
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.dependencies import get_db
from app.detection.scenario import run_scenario
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
