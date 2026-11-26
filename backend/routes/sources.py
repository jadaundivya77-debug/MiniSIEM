"""
Log Source Health Monitoring Routes for MiniSIEM X
Tracks collector heartbeats, ingestion timestamps, and source statuses
(CONNECTED, STALE, DISCONNECTED, STOPPED, ERROR, DEMO).
"""
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from typing import List
from datetime import datetime, timezone, timedelta

from backend.database import get_db
from backend.models import LogSource
from backend.schemas import LogSourceResponse, LogSourceCreate, CollectorHeartbeatRequest

router = APIRouter(prefix="/api/sources", tags=["Sources"])


def _as_utc(dt: datetime | None) -> datetime | None:
    if dt is None:
        return None
    return dt.replace(tzinfo=timezone.utc) if dt.tzinfo is None else dt.astimezone(timezone.utc)


def refresh_source_health(sources: List[LogSource]) -> None:
    """
    Computes live health status for each source.
    Never marks a collector CONNECTED merely because the backend is running.
    """
    now = datetime.now(timezone.utc)
    heartbeat_connected_window = timedelta(seconds=25)
    heartbeat_stale_window = timedelta(seconds=120)
    event_stale_window = timedelta(minutes=15)

    for s in sources:
        if s.source_type == "DEMO":
            s.status = "DEMO"
            continue

        if s.status == "STOPPED":
            continue

        if s.last_error:
            s.status = "ERROR"
            continue

        hb = _as_utc(s.last_heartbeat_at)
        last_ev = _as_utc(s.last_event_at)

        if hb is not None:
            age = now - hb
            if age <= heartbeat_connected_window:
                s.status = "CONNECTED"
            elif age <= heartbeat_stale_window:
                s.status = "STALE"
            else:
                s.status = "DISCONNECTED"
        elif last_ev is not None and (s.total_events or 0) > 0:
            s.status = "CONNECTED" if (now - last_ev) <= event_stale_window else "STALE"
        else:
            s.status = "DISCONNECTED"


@router.get("", response_model=List[LogSourceResponse])
def get_log_sources(db: Session = Depends(get_db)):
    """Returns registered log sources with live dynamic health calculation."""
    sources = db.query(LogSource).all()
    refresh_source_health(sources)
    db.commit()
    return sources


@router.post("/heartbeat", response_model=LogSourceResponse)
def collector_heartbeat(data: CollectorHeartbeatRequest, db: Session = Depends(get_db)):
    """Records live collector heartbeat, status transitions (CONNECTED/STOPPED/ERROR), and pending queue."""
    src_type = data.source_type.upper()
    src = db.query(LogSource).filter(
        (LogSource.source_type == src_type) | (LogSource.name == data.source_name)
    ).first()

    now = datetime.now(timezone.utc)
    req_status = data.status.upper().strip()
    if req_status not in {"CONNECTED", "STOPPED", "ERROR"}:
        req_status = "CONNECTED"

    if not src:
        src = LogSource(
            name=data.source_name,
            source_type=src_type,
            hostname=data.hostname,
            ip_address=data.ip_address,
            status=req_status,
            last_heartbeat_at=now,
            last_error=data.last_error if req_status == "ERROR" else None,
            pending_events=max(0, data.pending_events),
            total_events=0,
            error_count=1 if req_status == "ERROR" else 0,
        )
        db.add(src)
    else:
        if data.hostname:
            src.hostname = data.hostname
        if data.ip_address:
            src.ip_address = data.ip_address
        src.last_heartbeat_at = now
        src.pending_events = max(0, data.pending_events)
        if req_status == "ERROR":
            src.status = "ERROR"
            src.last_error = data.last_error or "Collector reported an error"
            src.error_count += 1
        elif req_status == "STOPPED":
            src.status = "STOPPED"
            src.last_error = None
        else:
            src.status = "CONNECTED"
            src.last_error = None

    db.commit()
    db.refresh(src)
    return src


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
        status="DISCONNECTED",
        last_event_at=None,
        last_heartbeat_at=None,
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

