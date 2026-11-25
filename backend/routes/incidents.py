"""
Incident Management API Routes for MiniSIEM X
Create incidents, update triage state, inspect chronological attack stories,
and assign analysts.
"""
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from typing import List, Optional, Dict, Any

from backend.database import get_db
from backend.models import Incident
from backend.schemas import IncidentResponse, IncidentCreate, IncidentUpdate
from backend.services.incident_service import IncidentService

router = APIRouter(prefix="/api/incidents", tags=["Incidents"])

@router.get("", response_model=List[IncidentResponse])
def get_incidents(
    status: Optional[str] = None,
    severity: Optional[str] = None,
    search: Optional[str] = None,
    limit: int = Query(50, le=100),
    offset: int = 0,
    db: Session = Depends(get_db)
):
    """Retrieves filtered security incidents."""
    incidents = IncidentService.get_incidents(db, status=status, severity=severity, search=search, limit=limit, offset=offset)
    # Populate events count
    for inc in incidents:
        inc.events_count = len(inc.incident_events) if inc.incident_events else 0
    return incidents

@router.post("", response_model=IncidentResponse)
def create_incident(
    data: IncidentCreate,
    db: Session = Depends(get_db)
):
    """Manually creates a new security incident."""
    incident = IncidentService.create_incident(
        db=db,
        title=data.title,
        description=data.description,
        severity=data.severity,
        assigned_analyst=data.assigned_analyst,
        investigation_notes=data.investigation_notes,
        related_alert_ids=data.related_alert_ids,
        related_log_ids=data.related_log_ids
    )
    incident.events_count = len(incident.incident_events) if incident.incident_events else 0
    return incident

@router.get("/{id}", response_model=IncidentResponse)
def get_incident_by_id(id: int, db: Session = Depends(get_db)):
    """Retrieves full details of an incident."""
    incident = IncidentService.get_incident_by_id(db, id)
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    incident.events_count = len(incident.incident_events) if incident.incident_events else 0
    return incident

@router.patch("/{id}", response_model=IncidentResponse)
def update_incident(
    id: int, 
    data: IncidentUpdate, 
    db: Session = Depends(get_db)
):
    """Updates incident status, assignment, root cause, or notes."""
    updated = IncidentService.update_incident(db, id, data.model_dump(exclude_unset=True))
    if not updated:
        raise HTTPException(status_code=404, detail="Incident not found")
    updated.events_count = len(updated.incident_events) if updated.incident_events else 0
    return updated

@router.get("/{id}/timeline")
def get_incident_timeline(id: int, db: Session = Depends(get_db)):
    """Retrieves the chronological Attack Story timeline with linked logs and alerts."""
    incident = IncidentService.get_incident_by_id(db, id)
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    timeline = IncidentService.get_incident_timeline(db, id)
    return {
        "incident_id": incident.id,
        "incident_number": incident.incident_number,
        "title": incident.title,
        "attack_story": incident.attack_story,
        "timeline": timeline
    }

