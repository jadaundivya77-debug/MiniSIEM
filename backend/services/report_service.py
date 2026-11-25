"""
Security Health & Compliance Reporting Service for MiniSIEM X
Aggregates SOC telemetry, detection metrics, risk posture, and generates CSV exports.
"""
import io
import csv
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional
from sqlalchemy.orm import Session
from sqlalchemy import func
from backend.models import LogEvent, Alert, Incident, Asset, LogSource

class ReportService:
    @staticmethod
    def generate_summary(db: Session) -> Dict[str, Any]:
        """Generates high-level SOC health metrics and breakdown."""
        total_events = db.query(LogEvent).count()
        total_alerts = db.query(Alert).count()
        total_incidents = db.query(Incident).count()
        open_incidents = db.query(Incident).filter(Incident.status == "OPEN").count()
        critical_incidents = db.query(Incident).filter(Incident.severity == "CRITICAL").count()
        resolved_incidents = db.query(Incident).filter(Incident.status == "RESOLVED").count()

        # Severity Breakdown of Alerts
        sev_counts = db.query(Alert.severity, func.count(Alert.id)).group_by(Alert.severity).all()
        alerts_by_sev = {sev: count for sev, count in sev_counts}

        # Detection Rule Frequency
        rule_counts = db.query(
            Alert.rule_id, Alert.rule_name, func.count(Alert.id)
        ).group_by(Alert.rule_id, Alert.rule_name).order_by(func.count(Alert.id).desc()).limit(5).all()
        top_rules = [{"rule_id": r[0], "rule_name": r[1], "count": r[2]} for r in rule_counts]

        # Top Suspicious Offending IPs
        ip_counts = db.query(
            Alert.source_ip, func.count(Alert.id)
        ).filter(Alert.source_ip != None).group_by(Alert.source_ip).order_by(func.count(Alert.id).desc()).limit(5).all()
        top_ips = [{"ip": r[0], "alert_count": r[1]} for r in ip_counts]

        # Riskiest Assets
        assets = db.query(Asset).order_by(Asset.risk_score.desc()).limit(5).all()
        top_assets = [
            {"name": a.name, "hostname": a.hostname, "ip": a.ip_address, "risk_score": a.risk_score, "risk_level": a.risk_level}
            for a in assets
        ]

        # Active Sources
        active_sources = db.query(LogSource).filter(LogSource.status.in_(["CONNECTED", "DEMO"])).count()

        return {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "kpis": {
                "total_events": total_events,
                "total_alerts": total_alerts,
                "total_incidents": total_incidents,
                "open_incidents": open_incidents,
                "critical_incidents": critical_incidents,
                "resolved_incidents": resolved_incidents,
                "active_sources": active_sources
            },
            "alerts_by_severity": alerts_by_sev,
            "top_detection_rules": top_rules,
            "top_suspicious_ips": top_ips,
            "top_risky_assets": top_assets,
            "recommendations": [
                "Implement automatic IP rate limiting on perimeter firewalls for top offending IPs.",
                "Mandate Multi-Factor Authentication (MFA) across all administrative accounts.",
                "Review privilege escalation sudo permissions on production web servers.",
                "Maintain continuous log source heartbeat ingestion to prevent stale monitoring gaps."
            ]
        }

    @staticmethod
    def export_alerts_csv(db: Session) -> str:
        """Exports all security alerts as formatted CSV data."""
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow([
            "Alert ID", "Timestamp (UTC)", "Severity", "Status", "Rule ID", 
            "Rule Name", "Title", "Source IP", "Target Username", "Affected Asset", 
            "Event Count", "MITRE ID", "MITRE Tactic"
        ])

        alerts = db.query(Alert).order_by(Alert.created_at.desc()).all()
        for a in alerts:
            writer.writerow([
                a.id,
                a.created_at.isoformat() if a.created_at else "",
                a.severity,
                a.status,
                a.rule_id,
                a.rule_name,
                a.title,
                a.source_ip or "",
                a.target_username or "",
                a.affected_asset or "",
                a.event_count,
                a.mitre_technique_id or "",
                a.mitre_tactic or ""
            ])

        return output.getvalue()

