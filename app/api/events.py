
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.dependencies import get_db
from app.models import Event, Host
from app.schemas import EventCreate, EventResponse


router = APIRouter(
    prefix="/api/v1/events",
    tags=["events"],
)


@router.post(
    "",
    response_model=EventResponse,
    status_code=status.HTTP_201_CREATED,
)
def create_event(
    event: EventCreate,
    db: Session = Depends(get_db),
):
    host = db.get(Host, event.host_id)

    if host is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Host with id {event.host_id} was not found.",
        )

    new_event = Event(
        host_id=event.host_id,
        timestamp=event.timestamp,
        event_type=event.event_type,
        event_data=event.event_data,
        raw_event=event.raw_event,
    )

    db.add(new_event)
    db.commit()
    db.refresh(new_event)

    return new_event


@router.get(
    "",
    response_model=list[EventResponse],
)
def list_events(
    db: Session = Depends(get_db),
):
    return db.query(Event).order_by(Event.id).all()
