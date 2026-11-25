"""
Alert Management Service for MiniSIEM X
Handles alert querying, status workflow transitions, and audit trail logging.
"""
from datetime import datetime, timezone
from typing import Optional, List, Dict, Any
from sqlalchemy.orm import Session
from backend.models import Alert, AuditLog

class AlertService:
    @staticmethod
    def get_alerts(
        db: Session,
        status: Optional[str] = None,
        severity: Optional[str] = None,
        search: Optional[str] = None,
        limit: int = 100,
        offset: int = 0
    ) -> List[Alert]:
        """Retrieves filtered alerts."""
        query = db.query(Alert)
        if status:
            query = query.filter(Alert.status == status.upper())
        if severity:
            query = query.filter(Alert.severity == severity.upper())
        if search:
            search_pattern = f"%{search}%"
            query = query.filter(
                (Alert.title.ilike(search_pattern)) |
                (Alert.source_ip.ilike(search_pattern)) |
                (Alert.target_username.ilike(search_pattern)) |
                (Alert.rule_id.ilike(search_pattern))
            )
        return query.order_by(Alert.created_at.desc()).offset(offset).limit(limit).all()

    @staticmethod
    def get_alert_by_id(db: Session, alert_id: int) -> Optional[Alert]:
        return db.query(Alert).filter(Alert.id == alert_id).first()

    @staticmethod
    def update_alert_status(
        db: Session,
        alert_id: int,
        status: str,
        user_name: str = "analyst",
        notes: Optional[str] = None
    ) -> Optional[Alert]:
        """Updates alert status and records an audit log entry."""
        alert = db.query(Alert).filter(Alert.id == alert_id).first()
        if not alert:
            return None

        old_status = alert.status
        alert.status = status.upper()
        alert.updated_at = datetime.now(timezone.utc)

        if status.upper() in ["RESOLVED", "FALSE_POSITIVE"]:
            alert.resolved_at = datetime.now(timezone.utc)
            alert.resolved_by = user_name

        # Record audit log
        audit = AuditLog(
            username=user_name,
            action="UPDATE_ALERT_STATUS",
            resource_type="ALERT",
            resource_id=str(alert_id),
            details=f"Status changed from {old_status} to {status}. Notes: {notes or 'None'}"
        )
        db.add(audit)
        db.commit()
        db.refresh(alert)
        return alert

