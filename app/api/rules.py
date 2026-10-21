from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.dependencies import get_db
from app.detection.rule_validator import (
    RuleValidationError,
    validate_rule_definition,
)
from app.models import Rule
from app.schemas import RuleCreate, RuleResponse


router = APIRouter(
    prefix="/api/v1/rules",
    tags=["rules"],
)


@router.post(
    "",
    response_model=RuleResponse,
    status_code=status.HTTP_201_CREATED,
)
def create_rule(
    rule: RuleCreate,
    db: Session = Depends(get_db),
):
    try:
        validate_rule_definition(
            rule.definition_yaml,
            rule.rule_id,
            {
                "name": rule.name,
                "description": rule.description,
                "platform": rule.platform,
                "severity": rule.severity,
            },
        )
    except RuleValidationError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(exc),
        ) from exc

    new_rule = Rule(
        rule_id=rule.rule_id,
        name=rule.name,
        description=rule.description,
        platform=rule.platform,
        definition_yaml=rule.definition_yaml,
        severity=rule.severity,
        mitre_technique=rule.mitre_technique,
        enabled=rule.enabled,
    )

    db.add(new_rule)

    try:
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Rule '{rule.rule_id}' already exists.",
        ) from exc

    db.refresh(new_rule)
    return new_rule


@router.get(
    "",
    response_model=list[RuleResponse],
)
def list_rules(
    db: Session = Depends(get_db),
):
    return db.query(Rule).order_by(Rule.id).all()