"""
Detection Rules Management Routes for MiniSIEM X
Query active rules, update detection thresholds, and toggle rule execution.
"""
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from typing import List
from datetime import datetime, timezone

from backend.database import get_db
from backend.models import DetectionRule, AuditLog
from backend.schemas import DetectionRuleResponse, DetectionRuleUpdate

router = APIRouter(prefix="/api/rules", tags=["Rules"])

@router.get("", response_model=List[DetectionRuleResponse])
def get_rules(db: Session = Depends(get_db)):
    """Retrieves all detection rules and MITRE mappings."""
    return db.query(DetectionRule).order_by(DetectionRule.rule_id.asc()).all()

@router.patch("/{id}", response_model=DetectionRuleResponse)
def update_rule(
    id: int,
    data: DetectionRuleUpdate,
    db: Session = Depends(get_db)
):
    """Enables/disables a rule or updates sliding time windows and thresholds."""
    rule = db.query(DetectionRule).filter(DetectionRule.id == id).first()
    if not rule:
        raise HTTPException(status_code=404, detail="Detection rule not found")

    if data.is_enabled is not None:
        rule.is_enabled = data.is_enabled
    if data.time_window_seconds is not None:
        rule.time_window_seconds = data.time_window_seconds
    if data.threshold_count is not None:
        rule.threshold_count = data.threshold_count
    if data.severity is not None:
        rule.severity = data.severity.upper()

    rule.updated_at = datetime.now(timezone.utc)

    # Audit log
    db.add(AuditLog(
        username="secadmin",
        action="UPDATE_DETECTION_RULE",
        resource_type="RULE",
        resource_id=rule.rule_id,
        details=f"Updated rule {rule.rule_id}: enabled={rule.is_enabled}, window={rule.time_window_seconds}s, threshold={rule.threshold_count}"
    ))
    db.commit()
    db.refresh(rule)
    return rule

