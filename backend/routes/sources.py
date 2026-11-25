"""
Log Source Health Monitoring Routes for MiniSIEM X
Tracks ingestion heartbeat, source statuses (CONNECTED, STALE, DISCONNECTED, DEMO), and ingestion errors.
"""
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from typing import List
from datetime import datetime, timezone, timedelta

from backend.database import get_db
from backend.models import LogSource
from backend.schemas import LogSourceResponse, LogSourceCreate

router = APIRouter(prefix="/api/sources", tags=["Sources"])

@router.get("", response_model=List[LogSourceResponse])
def get_log_sources(db: Session = Depends(get_db)):
    """
    Returns registered log sources with live dynamic health calculation.
    If connected source has not reported for > 15 minutes, marked STALE.
    """
    sources = db.query(LogSource).all()
    now = datetime.now(timezone.utc)
    stale_threshold = timedelta(minutes=15)

    for s in sources:
        if s.status == "CONNECTED" and s.last_event_at:
            # Handle tz-naive vs tz-aware
            last_event = s.last_event_at
            if last_event.tzinfo is None:
                last_event = last_event.replace(tzinfo=timezone.utc)
            if (now - last_event) > stale_threshold:
                s.status = "STALE"
        elif s.status != "DEMO" and not s.last_event_at:
            s.status = "DISCONNECTED"

    db.commit()
    return sources

@router.post("", response_model=LogSourceResponse)
def register_log_source(data: LogSourceCreate, db: Session = Depends(get_db)):
    """Registers a new log source to monitor."""
    existing = db.query(LogSource).filter(LogSource.name == data.name).first()
    if existing:
        raise HTTPException(status_code=400, detail="A log source with this name already exists")

    new_source = LogSource(
        name=data.name,
        source_type=data.source_type.upper(),
        hostname=data.hostname,
        ip_address=data.ip_address,
        status="CONNECTED",
        last_event_at=datetime.now(timezone.utc),
        total_events=0,
        error_count=0
    )
    db.add(new_source)
    db.commit()
    db.refresh(new_source)
    return new_source

@router.get("/{id}", response_model=LogSourceResponse)
def get_source_by_id(id: int, db: Session = Depends(get_db)):
    src = db.query(LogSource).filter(LogSource.id == id).first()
    if not src:
        raise HTTPException(status_code=404, detail="Log source not found")
    return src

