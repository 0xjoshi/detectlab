from pathlib import Path

from sqlalchemy.orm import Session

from app.database import Base, SessionLocal, engine
from app.detection.rule_validator import (
    RuleValidationError,
    validate_rule_definition,
)
from app.models import Rule

RULES_DIRECTORY = Path(__file__).resolve().parent.parent / "rules"


def seed_rules(db: Session, directory: Path = RULES_DIRECTORY) -> dict:
    """Load rule files into the database without overwriting existing rules."""
    created, existing, invalid = [], [], []

    for path in sorted(directory.glob("*.yaml")):
        text = path.read_text(encoding="utf-8")

        try:
            # The file name must match the rule ID inside the file.
            definition = validate_rule_definition(text, path.stem)
        except RuleValidationError as exc:
            invalid.append({"file": path.name, "reason": str(exc)})
            continue

        rule_id = definition["id"]

        if db.query(Rule).filter(Rule.rule_id == rule_id).first():
            existing.append(rule_id)
            continue

        db.add(
            Rule(
                rule_id=rule_id,
                name=definition["name"],
                description=definition["description"],
                platform=definition["platform"],
                definition_yaml=text,
                severity=definition["severity"],
                mitre_technique=definition.get("mitre_technique"),
                enabled=True,
            )
        )
        created.append(rule_id)

    db.commit()
    return {"created": created, "existing": existing, "invalid": invalid}


if __name__ == "__main__":
    Base.metadata.create_all(bind=engine)
    with SessionLocal() as session:
        print(seed_rules(session))