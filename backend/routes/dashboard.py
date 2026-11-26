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
from backend.routes.sources import refresh_source_health

router = APIRouter(prefix="/api/dashboard", tags=["Dashboard"])

@router.get("/stats")
def get_dashboard_stats(db: Session = Depends(get_db)):
    """Computes live SOC KPI metrics, severity breakdowns, and threat rankings."""
    sources = db.query(LogSource).all()
    refresh_source_health(sources)
    db.commit()

    total_events = db.query(LogEvent).count()
    total_alerts = db.query(Alert).count()
    critical_incidents = db.query(Incident).filter(Incident.severity == "CRITICAL").count()
    active_sources = sum(1 for s in sources if s.status in ("CONNECTED", "DEMO"))
    open_incidents = db.query(Incident).filter(Incident.status.in_(["OPEN", "INVESTIGATING"])).count()

    # Events processed today (last 24h)
    yesterday = datetime.now(timezone.utc) - timedelta(hours=24)
    events_today = db.query(LogEvent).filter(LogEvent.created_at >= yesterday).count()

    # Check real vs demo data breakdown
    demo_events_count = db.query(LogEvent).filter(LogEvent.is_demo == True).count()
    real_windows_events_count = db.query(LogEvent).filter(LogEvent.origin_type == "REAL_WINDOWS").count()
    real_events_count = total_events - demo_events_count
    demo_alerts_count = db.query(Alert).filter(Alert.is_demo == True).count()
    real_alerts_count = total_alerts - demo_alerts_count
    has_demo_events = demo_events_count > 0

    win_src = next((s for s in sources if s.source_type == "WINDOWS"), None)
    collector_status = {
        "status": win_src.status if win_src else "DISCONNECTED",
        "hostname": win_src.hostname if win_src else None,
        "last_heartbeat_at": win_src.last_heartbeat_at.isoformat() if win_src and win_src.last_heartbeat_at else None,
        "last_event_at": win_src.last_event_at.isoformat() if win_src and win_src.last_event_at else None,
        "last_error": win_src.last_error if win_src else None,
        "pending_events": win_src.pending_events if win_src else 0,
        "total_events": win_src.total_events if win_src else 0,
    }

    # Real 60-minute event volume buckets (6 x 10-minute buckets)
    now_utc = datetime.now(timezone.utc)
    recent_logs = db.query(LogEvent.created_at).filter(
        LogEvent.created_at >= now_utc - timedelta(minutes=60)
    ).all()
    bucket_counts = [0] * 6
    for (created_dt,) in recent_logs:
        if created_dt is None:
            continue
        if created_dt.tzinfo is None:
            created_dt = created_dt.replace(tzinfo=timezone.utc)
        age_mins = max(0.0, (now_utc - created_dt).total_seconds() / 60.0)
        idx = min(5, max(0, 5 - int(age_mins // 10)))
        bucket_counts[idx] += 1
    events_timeline = [
        {"label": label, "count": count}
        for label, count in zip(["-50m", "-40m", "-30m", "-20m", "-10m", "Now"], bucket_counts)
    ]

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
        "real_events_count": real_events_count,
        "real_windows_events_count": real_windows_events_count,
        "demo_events_count": demo_events_count,
        "real_alerts_count": real_alerts_count,
        "demo_alerts_count": demo_alerts_count,
        "collector_status": collector_status,
        "events_timeline": events_timeline,
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
            "origin_type": a.origin_type,
            "is_demo": a.is_demo,
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
            "origin_type": inc.origin_type,
            "is_demo": inc.is_demo,
            "timestamp": inc.created_at.isoformat(),
            "status": inc.status
        })

    feed.sort(key=lambda x: x["timestamp"], reverse=True)
    return feed[:10]

