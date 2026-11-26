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


def _update_log_source_stats(
    db: Session,
    source_key: str,
    hostname: Optional[str] = None,
    ip_address: Optional[str] = None,
    ingested_count: int = 1,
    error_count: int = 0,
    is_demo: bool = False,
):
    """Updates LogSource heartbeat, status, hostname, and counters on real/batch ingestion."""
    if ingested_count <= 0 and error_count <= 0:
        return

    src_upper = source_key.upper()
    src = db.query(LogSource).filter(
        (LogSource.source_type == src_upper) | (LogSource.name.ilike(f"%{source_key}%"))
    ).first()

    now = datetime.now(timezone.utc)
    if src:
        if not is_demo and src.source_type != "DEMO":
            src.status = "CONNECTED"
            src.last_heartbeat_at = now
            src.last_error = None
            src.pending_events = 0
            if hostname:
                src.hostname = hostname
            if ip_address:
                src.ip_address = ip_address
        src.last_event_at = now
        src.total_events += ingested_count
        src.error_count += error_count
        db.commit()
    elif not is_demo:
        db.add(LogSource(
            name=f"{source_key.title()} Event Collector",
            source_type=src_upper[:50],
            hostname=hostname or "localhost",
            ip_address=ip_address,
            status="CONNECTED",
            last_event_at=now,
            last_heartbeat_at=now,
            total_events=ingested_count,
            error_count=error_count,
        ))
        db.commit()


def _find_duplicate_windows_event(db: Session, norm: dict) -> Optional[LogEvent]:
    """Prevents duplicate Windows Event Log ingestion by (source, hostname, event_record_id)."""
    rec_id = norm.get("event_record_id")
    if rec_id is None or norm.get("source") != "windows":
        return None
    query = db.query(LogEvent).filter(
        LogEvent.source == "windows",
        LogEvent.event_record_id == rec_id,
    )
    if norm.get("hostname"):
        query = query.filter(LogEvent.hostname == norm["hostname"])
    return query.first()


def _create_log_event_from_norm(norm: dict) -> LogEvent:
    """Builds a LogEvent ORM object from a normalized event dictionary."""
    return LogEvent(
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
        event_record_id=norm.get("event_record_id"),
        origin_type=norm.get("origin_type"),
        is_demo=norm["is_demo"],
    )


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
    if not raw_data.get("origin_type") and not event_in.is_demo:
        meta_dict = raw_data.get("metadata") or {}
        if not (event_in.source.lower() == "windows" and (meta_dict.get("collector") == "windows_event_log" or meta_dict.get("EventRecordID"))):
            raw_data["origin_type"] = "MANUAL_INGEST"
    norm = EventNormalizer.normalize(raw_data, default_source=event_in.source, is_demo=event_in.is_demo)
    
    is_valid, errors = LogValidator.validate(norm)
    if not is_valid:
        raise HTTPException(status_code=400, detail={"errors": errors})

    existing = _find_duplicate_windows_event(db, norm)
    if existing:
        return existing

    log_entry = _create_log_event_from_norm(norm)
    db.add(log_entry)
    db.commit()
    db.refresh(log_entry)

    _update_log_source_stats(
        db,
        source_key=norm["source"],
        hostname=norm["hostname"],
        ip_address=norm["destination_ip"],
        ingested_count=1,
        is_demo=norm["is_demo"],
    )

    # Pass through detection engine
    engine = DetectionEngine(db)
    engine.process_event(log_entry)

    return log_entry

@router.post("/batch")
def ingest_batch_events(
    batch: LogBatchRequest, 
    db: Session = Depends(get_db)
):
    """Ingests a batch of events in a single HTTP transaction with duplicate prevention."""
    ingested_count = 0
    duplicates_skipped = 0
    alerts_triggered = 0
    errors = []
    engine = DetectionEngine(db)
    last_source = batch.source_name or "custom"
    last_hostname = None
    last_is_demo = False

    for item in batch.events:
        raw_dict = item.model_dump()
        source = batch.source_name or item.source
        norm = EventNormalizer.normalize(raw_dict, default_source=source, is_demo=item.is_demo)
        is_valid, errs = LogValidator.validate(norm)
        if not is_valid:
            errors.append(f"Event failed validation: {', '.join(errs)}")
            continue

        if _find_duplicate_windows_event(db, norm):
            duplicates_skipped += 1
            last_source = norm["source"]
            last_hostname = norm["hostname"] or last_hostname
            last_is_demo = norm["is_demo"]
            continue

        log_entry = _create_log_event_from_norm(norm)
        db.add(log_entry)
        db.commit()
        db.refresh(log_entry)

        last_source = norm["source"]
        last_hostname = norm["hostname"] or last_hostname
        last_is_demo = norm["is_demo"]

        triggered = engine.process_event(log_entry)
        alerts_triggered += len(triggered)
        ingested_count += 1

    if ingested_count > 0 or duplicates_skipped > 0 or errors:
        _update_log_source_stats(
            db,
            source_key=last_source,
            hostname=last_hostname,
            ingested_count=ingested_count,
            error_count=len(errors),
            is_demo=last_is_demo,
        )

    return {
        "status": "success",
        "total_submitted": len(batch.events),
        "total_ingested": ingested_count,
        "duplicates_skipped": duplicates_skipped,
        "alerts_triggered": alerts_triggered,
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
        if isinstance(record, dict) and not record.get("origin_type"):
            record["origin_type"] = "FILE_IMPORT"
        norm = EventNormalizer.normalize(record, default_source=source_name, is_demo=False)
        is_valid, errs = LogValidator.validate(norm)
        if not is_valid:
            errors.append(f"Row error: {', '.join(errs)}")
            continue

        log_entry = _create_log_event_from_norm(norm)
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
    is_demo: Optional[bool] = None,
    origin_type: Optional[str] = None,
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
    if is_demo is not None:
        query = query.filter(LogEvent.is_demo == is_demo)
    if origin_type:
        query = query.filter(LogEvent.origin_type == origin_type.upper())
    if search:
        pat = f"%{search}%"
        query = query.filter(
            (LogEvent.raw_event.ilike(pat)) |
            (LogEvent.source_ip.ilike(pat)) |
            (LogEvent.username.ilike(pat)) |
            (LogEvent.hostname.ilike(pat)) |
            (LogEvent.event_type.ilike(pat))
        )
    return query.order_by(LogEvent.timestamp.desc()).offset(offset).limit(limit).all()

@router.get("/{id}", response_model=LogEventResponse)
def get_log_by_id(id: int, db: Session = Depends(get_db)):
    """Retrieves details of a specific log event."""
    log = db.query(LogEvent).filter(LogEvent.id == id).first()
    if not log:
        raise HTTPException(status_code=404, detail="Log event not found")
    return log

