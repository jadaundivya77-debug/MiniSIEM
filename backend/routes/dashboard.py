"""
Dashboard Statistics & Telemetry Feeds for MiniSIEM X
Supplies real-time aggregated metrics directly from database queries.
"""
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from sqlalchemy import func
from datetime import datetime, timezone, timedelta

from backend.database import get_db
from backend.models import LogEvent, Alert, Incident, LogSource, Asset, DetectionRule

router = APIRouter(prefix="/api/dashboard", tags=["Dashboard"])

@router.get("/stats")
def get_dashboard_stats(db: Session = Depends(get_db)):
    """Computes live SOC KPI metrics, severity breakdowns, and threat rankings."""
    total_events = db.query(LogEvent).count()
    total_alerts = db.query(Alert).count()
    critical_incidents = db.query(Incident).filter(Incident.severity == "CRITICAL").count()
    active_sources = db.query(LogSource).filter(LogSource.status.in_(["CONNECTED", "DEMO"])).count()
    open_incidents = db.query(Incident).filter(Incident.status.in_(["OPEN", "INVESTIGATING"])).count()

    # Events processed today (last 24h)
    yesterday = datetime.now(timezone.utc) - timedelta(hours=24)
    events_today = db.query(LogEvent).filter(LogEvent.created_at >= yesterday).count()

    # Check if demo data exists
    has_demo_events = db.query(LogEvent).filter(LogEvent.is_demo == True).first() is not None

    # Severity distribution
    sev_query = db.query(Alert.severity, func.count(Alert.id)).group_by(Alert.severity).all()
    alerts_by_sev = {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0}
    for s, count in sev_query:
        if s in alerts_by_sev:
            alerts_by_sev[s] = count

    # Incident status distribution
    status_query = db.query(Incident.status, func.count(Incident.id)).group_by(Incident.status).all()
    incidents_by_status = {"OPEN": 0, "INVESTIGATING": 0, "RESOLVED": 0, "FALSE_POSITIVE": 0}
    for st, count in status_query:
        if st in incidents_by_status:
            incidents_by_status[st] = count

    # Attack types distribution (by rule)
    attack_types_query = db.query(
        Alert.rule_name, func.count(Alert.id)
    ).group_by(Alert.rule_name).order_by(func.count(Alert.id).desc()).limit(6).all()
    top_attack_types = [{"name": r[0], "count": r[1]} for r in attack_types_query]

    # Events by Log Source
    source_query = db.query(
        LogEvent.source, func.count(LogEvent.id)
    ).group_by(LogEvent.source).all()
    events_by_source = [{"source": r[0], "count": r[1]} for r in source_query]

    # Top suspicious source IPs
    suspicious_ips_query = db.query(
        Alert.source_ip, func.count(Alert.id)
    ).filter(Alert.source_ip != None).group_by(Alert.source_ip).order_by(func.count(Alert.id).desc()).limit(5).all()
    top_suspicious_ips = [{"ip": r[0], "count": r[1]} for r in suspicious_ips_query]

    # Top Risky Assets
    risky_assets = db.query(Asset).order_by(Asset.risk_score.desc()).limit(4).all()
    top_risky_assets = [
        {"name": a.name, "hostname": a.hostname, "ip": a.ip_address, "risk_score": a.risk_score, "risk_level": a.risk_level}
        for a in risky_assets
    ]

    # Detection Engine Health
    total_rules = db.query(DetectionRule).count()
    enabled_rules = db.query(DetectionRule).filter(DetectionRule.is_enabled == True).count()

    return {
        "total_events": total_events,
        "total_alerts": total_alerts,
        "critical_incidents": critical_incidents,
        "active_sources": active_sources,
        "open_incidents": open_incidents,
        "events_processed_today": events_today,
        "is_demo": has_demo_events,
        "alerts_by_severity": alerts_by_sev,
        "incidents_by_status": incidents_by_status,
        "top_attack_types": top_attack_types,
        "events_by_source": events_by_source,
        "top_suspicious_ips": top_suspicious_ips,
        "top_risky_assets": top_risky_assets,
        "detection_engine_status": {
            "status": "OPERATIONAL",
            "total_rules": total_rules,
            "active_rules": enabled_rules,
            "version": "MiniSIEM X v1.0.0"
        }
    }

@router.get("/timeline")
def get_dashboard_timeline(db: Session = Depends(get_db)):
    """Provides combined chronological activity feed of recent alerts and incidents."""
    recent_alerts = db.query(Alert).order_by(Alert.created_at.desc()).limit(6).all()
    recent_incidents = db.query(Incident).order_by(Incident.created_at.desc()).limit(4).all()

    feed = []
    for a in recent_alerts:
        feed.append({
            "type": "ALERT",
            "id": a.id,
            "title": a.title,
            "severity": a.severity,
            "source_ip": a.source_ip,
            "timestamp": a.created_at.isoformat(),
            "rule_id": a.rule_id
        })
    for inc in recent_incidents:
        feed.append({
            "type": "INCIDENT",
            "id": inc.id,
            "title": f"[{inc.incident_number}] {inc.title}",
            "severity": inc.severity,
            "source_ip": None,
            "timestamp": inc.created_at.isoformat(),
            "status": inc.status
        })

    feed.sort(key=lambda x: x["timestamp"], reverse=True)
    return feed[:10]

