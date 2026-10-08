from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.dependencies import get_db
from app.models import Host
from app.schemas import HostCreate, HostResponse


router = APIRouter(
    prefix="/api/v1/hosts",
    tags=["hosts"],
)


@router.post(
    "",
    response_model=HostResponse,
    status_code=status.HTTP_201_CREATED,
)
def create_host(
    host: HostCreate,
    db: Session = Depends(get_db),
):
    new_host = Host(
        hostname=host.hostname,
        platform=host.platform,
        ip_address=host.ip_address,
    )

    db.add(new_host)

    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Host '{host.hostname}' already exists.",
        )

    db.refresh(new_host)

    return new_host


@router.get(
    "",
    response_model=list[HostResponse],
)
def list_hosts(
    db: Session = Depends(get_db),
):
    return db.query(Host).order_by(Host.id).all()