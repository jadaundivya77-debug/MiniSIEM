"""
Security Alerts API Routes for MiniSIEM X
Query alerts, inspect explainable evidence, update status, and track remediation.
"""
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from typing import List, Optional

from backend.database import get_db
from backend.models import Alert
from backend.schemas import AlertResponse, AlertUpdate
from backend.services.alert_service import AlertService

router = APIRouter(prefix="/api/alerts", tags=["Alerts"])

@router.get("", response_model=List[AlertResponse])
def get_alerts(
    status: Optional[str] = None,
    severity: Optional[str] = None,
    search: Optional[str] = None,
    limit: int = Query(100, le=500),
    offset: int = 0,
    db: Session = Depends(get_db)
):
    """Returns filtered security alerts."""
    return AlertService.get_alerts(db, status=status, severity=severity, search=search, limit=limit, offset=offset)

@router.get("/{id}", response_model=AlertResponse)
def get_alert_by_id(id: int, db: Session = Depends(get_db)):
    """Retrieves full details and explainability for a specific alert."""
    alert = AlertService.get_alert_by_id(db, id)
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    return alert

@router.patch("/{id}", response_model=AlertResponse)
def update_alert(
    id: int, 
    update_data: AlertUpdate, 
    db: Session = Depends(get_db)
):
    """Updates alert status (OPEN, INVESTIGATING, RESOLVED, FALSE_POSITIVE)."""
    updated = AlertService.update_alert_status(
        db, 
        alert_id=id, 
        status=update_data.status, 
        notes=update_data.notes
    )
    if not updated:
        raise HTTPException(status_code=404, detail="Alert not found")
    return updated

