from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.dependencies import get_db
from app.detection.service import evaluate_enabled_rules
from app.schemas import DetectionEvaluationRequest

router = APIRouter(
    prefix="/api/v1/detections",
    tags=["detections"],
)


@router.post("/evaluate")
def evaluate_detections(
    request: DetectionEvaluationRequest,
    db: Session = Depends(get_db),
):
    return evaluate_enabled_rules(
        db=db,
        evaluation_time=request.evaluation_time,
    )