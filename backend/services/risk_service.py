"""
Asset Risk Scoring Service for MiniSIEM X
Transparent, mathematically explainable risk calculation based on:
1. Asset Criticality baseline weight
2. Associated security alerts count and severity
3. Open incident associations
4. Recent suspicious telemetry frequency
"""
from typing import Dict, Any, Tuple
from sqlalchemy.orm import Session
from backend.models import Asset, Alert, Incident

CRITICALITY_WEIGHTS = {
    "LOW": 10.0,
    "MEDIUM": 25.0,
    "HIGH": 50.0,
    "CRITICAL": 75.0
}

ALERT_SEVERITY_POINTS = {
    "CRITICAL": 30.0,
    "HIGH": 20.0,
    "MEDIUM": 10.0,
    "LOW": 5.0,
    "INFO": 1.0
}

def calculate_asset_risk(asset: Asset, db: Session) -> Tuple[float, str, Dict[str, Any]]:
    """
    Calculates explainable risk score (0.0 to 100.0) and returns:
    (risk_score, risk_level, risk_factors_breakdown)
    """
    breakdown = {}

    # 1. Base Score from Asset Criticality
    crit = asset.criticality.upper() if asset.criticality else "MEDIUM"
    base_points = CRITICALITY_WEIGHTS.get(crit, 25.0) * 0.25  # Contribution up to 18.75 pts
    breakdown["asset_criticality"] = {
        "level": crit,
        "points_contributed": round(base_points, 1),
        "explanation": f"Baseline criticality rating of {crit}"
    }

    # 2. Associated Alerts Contribution
    alerts = db.query(Alert).filter(
        (Alert.affected_asset.ilike(f"%{asset.hostname}%")) |
        (Alert.affected_asset.ilike(f"%{asset.name}%")) |
        (Alert.source_ip == asset.ip_address)
    ).all()

    alert_points = 0.0
    severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for a in alerts:
        sev = a.severity.upper() if a.severity else "LOW"
        severity_counts[sev] = severity_counts.get(sev, 0) + 1
        # Open alerts weigh 100%, resolved alerts weigh 20%
        weight = 1.0 if a.status in ["OPEN", "INVESTIGATING"] else 0.2
        alert_points += ALERT_SEVERITY_POINTS.get(sev, 5.0) * weight

    # Cap alert points contribution at 50 pts
    capped_alert_points = min(alert_points, 50.0)
    breakdown["alert_threats"] = {
        "total_associated_alerts": len(alerts),
        "active_severity_counts": severity_counts,
        "points_contributed": round(capped_alert_points, 1),
        "explanation": f"Accumulated points from {len(alerts)} alerts (unresolved weighted heavily)"
    }

    # 3. Open Incidents Contribution
    incidents = db.query(Incident).filter(
        (Incident.title.ilike(f"%{asset.hostname}%")) |
        (Incident.title.ilike(f"%{asset.name}%")),
        Incident.status.in_(["OPEN", "INVESTIGATING"])
    ).count()

    incident_points = min(incidents * 25.0, 30.0)
    breakdown["open_incidents"] = {
        "open_incident_count": incidents,
        "points_contributed": round(incident_points, 1),
        "explanation": f"{incidents} active unresolved incidents directly referencing this asset"
    }

    # Total Raw Score (0 - 100)
    total_score = min(round(base_points + capped_alert_points + incident_points, 1), 100.0)

    # Determine Risk Level Category
    if total_score >= 80.0:
        risk_level = "CRITICAL"
    elif total_score >= 55.0:
        risk_level = "HIGH"
    elif total_score >= 30.0:
        risk_level = "MEDIUM"
    else:
        risk_level = "LOW"

    breakdown["total_score"] = total_score
    breakdown["risk_level"] = risk_level
    breakdown["algorithm_version"] = "MiniSIEM-X-RiskEngine-v1.0"

    return total_score, risk_level, breakdown

