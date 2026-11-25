"""
Log Ingestion & Query Routes for MiniSIEM X
Supports single event ingest, batch ingestion, file uploads (JSON/JSONL/CSV),
and real-time normalized event queries with filters.
"""
from fastapi import APIRouter, Depends, HTTPException, UploadFile, File, Form, Query
from sqlalchemy.orm import Session
from typing import List, Optional
from datetime import datetime, timezone

from backend.database import get_db
from backend.models import LogEvent, LogSource
from backend.schemas import LogEventCreate, LogEventResponse, LogBatchRequest, LogUploadResponse
from backend.processors.parser import LogParser
from backend.processors.normalizer import EventNormalizer
from backend.processors.validator import LogValidator
from backend.detection.engine import DetectionEngine

router = APIRouter(prefix="/api/logs", tags=["Logs"])

@router.post("/ingest", response_model=LogEventResponse)
def ingest_single_event(
    event_in: LogEventCreate, 
    db: Session = Depends(get_db)
):
    """
    Ingests a single raw event, normalizes it, stores it,
    and runs it through the threat detection engine.
    """
    raw_data = event_in.model_dump()
    norm = EventNormalizer.normalize(raw_data, default_source=event_in.source, is_demo=event_in.is_demo)
    
    is_valid, errors = LogValidator.validate(norm)
    if not is_valid:
        raise HTTPException(status_code=400, detail={"errors": errors})

    log_entry = LogEvent(
        timestamp=norm["timestamp"],
        source=norm["source"],
        hostname=norm["hostname"],
        event_type=norm["event_type"],
        username=norm["username"],
        source_ip=norm["source_ip"],
        destination_ip=norm["destination_ip"],
        destination_port=norm["destination_port"],
        severity=norm["severity"],
        raw_event=norm["raw_event"],
        metadata_json=norm["metadata_json"],
        is_demo=norm["is_demo"]
    )
    db.add(log_entry)
    db.commit()
    db.refresh(log_entry)

    # Update LogSource health telemetry
    src = db.query(LogSource).filter(LogSource.name.ilike(f"%{norm['source']}%")).first()
    if src:
        src.last_event_at = datetime.now(timezone.utc)
        src.total_events += 1
        db.commit()

    # Pass through detection engine
    engine = DetectionEngine(db)
    engine.process_event(log_entry)

    return log_entry

@router.post("/batch")
def ingest_batch_events(
    batch: LogBatchRequest, 
    db: Session = Depends(get_db)
):
    """Ingests a batch of events in a single HTTP transaction."""
    ingested_count = 0
    errors = []
    engine = DetectionEngine(db)

    for item in batch.events:
        raw_dict = item.model_dump()
        source = batch.source_name or item.source
        norm = EventNormalizer.normalize(raw_dict, default_source=source, is_demo=item.is_demo)
        is_valid, errs = LogValidator.validate(norm)
        if not is_valid:
            errors.append(f"Event failed validation: {', '.join(errs)}")
            continue

        log_entry = LogEvent(
            timestamp=norm["timestamp"],
            source=norm["source"],
            hostname=norm["hostname"],
            event_type=norm["event_type"],
            username=norm["username"],
            source_ip=norm["source_ip"],
            destination_ip=norm["destination_ip"],
            destination_port=norm["destination_port"],
            severity=norm["severity"],
            raw_event=norm["raw_event"],
            metadata_json=norm["metadata_json"],
            is_demo=norm["is_demo"]
        )
        db.add(log_entry)
        db.commit()
        db.refresh(log_entry)

        engine.process_event(log_entry)
        ingested_count += 1

    return {
        "status": "success",
        "total_submitted": len(batch.events),
        "total_ingested": ingested_count,
        "errors_count": len(errors),
        "errors": errors[:5]
    }

@router.post("/upload", response_model=LogUploadResponse)
async def upload_log_file(
    file: UploadFile = File(...),
    source_name: str = Form("file_import"),
    db: Session = Depends(get_db)
):
    """
    Handles file upload (JSON, JSONL, CSV, Text), extracts and validates events,
    and runs them through the threat detection engine.
    """
    content = await file.read()
    raw_records = LogParser.parse(content)

    ingested = 0
    errors = []
    sample_preview = []
    engine = DetectionEngine(db)

    for record in raw_records:
        norm = EventNormalizer.normalize(record, default_source=source_name, is_demo=False)
        is_valid, errs = LogValidator.validate(norm)
        if not is_valid:
            errors.append(f"Row error: {', '.join(errs)}")
            continue

        log_entry = LogEvent(
            timestamp=norm["timestamp"],
            source=norm["source"],
            hostname=norm["hostname"],
            event_type=norm["event_type"],
            username=norm["username"],
            source_ip=norm["source_ip"],
            destination_ip=norm["destination_ip"],
            destination_port=norm["destination_port"],
            severity=norm["severity"],
            raw_event=norm["raw_event"],
            metadata_json=norm["metadata_json"],
            is_demo=norm["is_demo"]
        )
        db.add(log_entry)
        db.commit()
        db.refresh(log_entry)

        engine.process_event(log_entry)
        ingested += 1

        if len(sample_preview) < 5:
            sample_preview.append({
                "timestamp": norm["timestamp"].isoformat(),
                "event_type": norm["event_type"],
                "source_ip": norm["source_ip"],
                "username": norm["username"],
                "severity": norm["severity"]
            })

    # Update or register source
    src = db.query(LogSource).filter(LogSource.name == source_name).first()
    if not src:
        src = LogSource(
            name=source_name,
            source_type="FILE",
            hostname="uploaded-file",
            status="CONNECTED",
            last_event_at=datetime.now(timezone.utc),
            total_events=ingested,
            error_count=len(errors)
        )
        db.add(src)
    else:
        src.last_event_at = datetime.now(timezone.utc)
        src.total_events += ingested
        src.error_count += len(errors)
    db.commit()

    return {
        "total_received": len(raw_records),
        "total_ingested": ingested,
        "total_errors": len(errors),
        "errors": errors[:5],
        "source": source_name,
        "sample_preview": sample_preview
    }

@router.get("", response_model=List[LogEventResponse])
def get_logs(
    source: Optional[str] = None,
    event_type: Optional[str] = None,
    severity: Optional[str] = None,
    source_ip: Optional[str] = None,
    username: Optional[str] = None,
    search: Optional[str] = None,
    limit: int = Query(50, le=200),
    offset: int = 0,
    db: Session = Depends(get_db)
):
    """Retrieves paginated and filtered normalized security events."""
    query = db.query(LogEvent)
    if source:
        query = query.filter(LogEvent.source == source.lower())
    if event_type:
        query = query.filter(LogEvent.event_type == event_type.lower())
    if severity:
        query = query.filter(LogEvent.severity == severity.upper())
    if source_ip:
        query = query.filter(LogEvent.source_ip == source_ip)
    if username:
        query = query.filter(LogEvent.username == username)
    if search:
        pat = f"%{search}%"
        query = query.filter(
            (LogEvent.raw_event.ilike(pat)) |
            (LogEvent.source_ip.ilike(pat)) |
            (LogEvent.username.ilike(pat)) |
            (LogEvent.hostname.ilike(pat))
        )
    return query.order_by(LogEvent.timestamp.desc()).offset(offset).limit(limit).all()

@router.get("/{id}", response_model=LogEventResponse)
def get_log_by_id(id: int, db: Session = Depends(get_db)):
    """Retrieves details of a specific log event."""
    log = db.query(LogEvent).filter(LogEvent.id == id).first()
    if not log:
        raise HTTPException(status_code=404, detail="Log event not found")
    return log

