"""
Incident Management Service for MiniSIEM X
Provides incident lifecycle handling, assignment, attack story timeline assembly, and status updates.
"""
from datetime import datetime, timezone
from typing import Optional, List, Dict, Any
from sqlalchemy.orm import Session
from backend.models import Incident, IncidentEvent, LogEvent, Alert, AuditLog

class IncidentService:
    @staticmethod
    def get_incidents(
        db: Session,
        status: Optional[str] = None,
        severity: Optional[str] = None,
        search: Optional[str] = None,
        limit: int = 50,
        offset: int = 0
    ) -> List[Incident]:
        """Retrieves filtered security incidents."""
        query = db.query(Incident)
        if status:
            query = query.filter(Incident.status == status.upper())
        if severity:
            query = query.filter(Incident.severity == severity.upper())
        if search:
            search_pat = f"%{search}%"
            query = query.filter(
                (Incident.incident_number.ilike(search_pat)) |
                (Incident.title.ilike(search_pat)) |
                (Incident.assigned_analyst.ilike(search_pat))
            )
        return query.order_by(Incident.created_at.desc()).offset(offset).limit(limit).all()

    @staticmethod
    def get_incident_by_id(db: Session, incident_id: int) -> Optional[Incident]:
        return db.query(Incident).filter(Incident.id == incident_id).first()

    @staticmethod
    def create_incident(
        db: Session,
        title: str,
        description: str,
        severity: str = "HIGH",
        assigned_analyst: Optional[str] = None,
        investigation_notes: Optional[str] = None,
        related_alert_ids: Optional[List[int]] = None,
        related_log_ids: Optional[List[int]] = None,
        created_by: str = "analyst"
    ) -> Incident:
        """Manually creates an incident and associates alerts & logs."""
        count = db.query(Incident).count() + 1
        inc_number = f"INC-2026-{count:04d}"

        incident = Incident(
            incident_number=inc_number,
            title=title,
            description=description,
            severity=severity.upper(),
            status="OPEN",
            assigned_analyst=assigned_analyst or "Unassigned",
            investigation_notes=investigation_notes,
            created_at=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc)
        )
        db.add(incident)
        db.commit()
        db.refresh(incident)

        # Attach related alerts
        order = 0
        if related_alert_ids:
            for aid in related_alert_ids:
                order += 1
                db.add(IncidentEvent(
                    incident_id=incident.id,
                    alert_id=aid,
                    stage="Alert Correlation",
                    note=f"Associated Alert #{aid}",
                    order_index=order
                ))

        if related_log_ids:
            for lid in related_log_ids:
                order += 1
                db.add(IncidentEvent(
                    incident_id=incident.id,
                    log_event_id=lid,
                    stage="Evidence Log",
                    note=f"Associated Telemetry Log #{lid}",
                    order_index=order
                ))

        # Audit log
        db.add(AuditLog(
            username=created_by,
            action="CREATE_INCIDENT",
            resource_type="INCIDENT",
            resource_id=str(incident.id),
            details=f"Created incident {inc_number}: '{title}'"
        ))
        db.commit()
        db.refresh(incident)
        return incident

    @staticmethod
    def update_incident(
        db: Session,
        incident_id: int,
        updates: Dict[str, Any],
        user_name: str = "analyst"
    ) -> Optional[Incident]:
        """Updates incident fields (status, analyst, notes, root cause) with audit history."""
        incident = db.query(Incident).filter(Incident.id == incident_id).first()
        if not incident:
            return None

        old_status = incident.status
        for k, v in updates.items():
            if v is not None and hasattr(incident, k):
                setattr(incident, k, v)

        incident.updated_at = datetime.now(timezone.utc)
        if updates.get("status") in ["RESOLVED", "FALSE_POSITIVE"]:
            incident.resolved_at = datetime.now(timezone.utc)
            incident.resolved_by = user_name

        db.add(AuditLog(
            username=user_name,
            action="UPDATE_INCIDENT",
            resource_type="INCIDENT",
            resource_id=str(incident_id),
            details=f"Incident {incident.incident_number} updated: status {old_status}->{incident.status}"
        ))
        db.commit()
        db.refresh(incident)
        return incident

    @staticmethod
    def get_incident_timeline(db: Session, incident_id: int) -> List[Dict[str, Any]]:
        """Constructs an integrated chronological event timeline for the incident."""
        timeline_entries = []
        links = db.query(IncidentEvent).filter(
            IncidentEvent.incident_id == incident_id
        ).order_by(IncidentEvent.order_index.asc()).all()

        for link in links:
            entry = {
                "id": link.id,
                "stage": link.stage or "Investigation Step",
                "note": link.note,
                "created_at": link.created_at.isoformat(),
                "log": None,
                "alert": None
            }
            if link.log_event_id:
                log = db.query(LogEvent).filter(LogEvent.id == link.log_event_id).first()
                if log:
                    entry["log"] = {
                        "id": log.id,
                        "timestamp": log.timestamp.isoformat(),
                        "event_type": log.event_type,
                        "source": log.source,
                        "source_ip": log.source_ip,
                        "username": log.username,
                        "severity": log.severity,
                        "raw_event": log.raw_event
                    }
            if link.alert_id:
                alert = db.query(Alert).filter(Alert.id == link.alert_id).first()
                if alert:
                    entry["alert"] = {
                        "id": alert.id,
                        "title": alert.title,
                        "rule_id": alert.rule_id,
                        "severity": alert.severity,
                        "created_at": alert.created_at.isoformat()
                    }
            timeline_entries.append(entry)

        return timeline_entries

