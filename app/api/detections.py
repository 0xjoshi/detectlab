from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.dependencies import get_db
from app.detection.service import evaluate_enabled_rules
from app.detection.validation import validate_detection
from app.schemas import (
    DetectionEvaluationRequest,
    DetectionValidationRequest,
)

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


@router.post("/validate")
def validate_detections(
    request: DetectionValidationRequest,
    db: Session = Depends(get_db),
):
    evaluation = evaluate_enabled_rules(
        db=db,
        evaluation_time=request.evaluation_time,
    )

    validation = validate_detection(
        expected_rule_id=request.expected_rule_id,
        expected_host=request.expected_host,
        detections=evaluation["detections"],
    )

    return {
        **validation,
        "evaluation_time": evaluation["evaluation_time"],
        "rules_evaluated": evaluation["rules_evaluated"],
        "rules_skipped": evaluation["rules_skipped"],
        "detections": evaluation["detections"],
    }