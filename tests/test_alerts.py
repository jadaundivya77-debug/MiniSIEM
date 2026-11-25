import pytest
from datetime import datetime, timezone
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from backend.models import Base, Alert, Incident, LogEvent, Asset
from backend.services.alert_service import AlertService
from backend.services.incident_service import IncidentService
from backend.services.explanation_service import generate_alert_explanation
from backend.services.risk_service import calculate_asset_risk

@pytest.fixture
def alert_db():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(bind=engine)
    Session = sessionmaker(bind=engine)
    session = Session()

    # Seed asset
    asset = Asset(
        name="Primary Gateway",
        hostname="gw01.prod",
        ip_address="192.168.1.1",
        os_type="Linux Ubuntu",
        asset_type="SERVER",
        criticality="HIGH",
        risk_score=20.0,
        risk_level="LOW"
    )
    session.add(asset)
    session.commit()

    yield session
    session.close()

def test_alert_lifecycle_and_audit(alert_db):
    alert = Alert(
        title="Test Brute Force Alert",
        description="5 failed logins",
        rule_id="RULE-001",
        rule_name="Brute-Force Detection",
        severity="HIGH",
        status="OPEN",
        source_ip="198.51.100.24",
        target_username="admin",
        event_count=5
    )
    alert_db.add(alert)
    alert_db.commit()
    alert_db.refresh(alert)

    # Update status to RESOLVED
    updated = AlertService.update_alert_status(
        alert_db, alert_id=alert.id, status="RESOLVED", user_name="secanalyst", notes="Legitimate sysadmin testing."
    )
    assert updated.status == "RESOLVED"
    assert updated.resolved_by == "secanalyst"
    assert updated.resolved_at is not None

def test_explainable_alert_generation():
    alert_data = {
        "rule_id": "RULE-001",
        "rule_name": "Brute-Force Login Detection",
        "source_ip": "198.51.100.24",
        "target_username": "admin",
        "affected_asset": "gw01.prod",
        "event_count": 6,
        "time_window_seconds": 120,
        "evidence": {"failed_attempts": 6, "threshold": 5}
    }
    explanation = generate_alert_explanation(alert_data)
    assert "WHAT HAPPENED:" in explanation
    assert "WHY IS IT SUSPICIOUS:" in explanation
    assert "198.51.100.24" in explanation
    assert "admin" in explanation
    assert "T1110" in explanation

def test_incident_timeline_assembly(alert_db):
    inc = IncidentService.create_incident(
        db=alert_db,
        title="Active Attack on Domain Controller",
        description="Correlated credential access",
        severity="CRITICAL",
        assigned_analyst="Tier-2 Analyst",
        created_by="system"
    )
    assert inc.incident_number.startswith("INC-2026-")
    assert inc.status == "OPEN"

    # Update status
    updated = IncidentService.update_incident(
        alert_db, inc.id, {"status": "INVESTIGATING", "investigation_notes": "Host isolated."}
    )
    assert updated.status == "INVESTIGATING"
    assert updated.investigation_notes == "Host isolated."

def test_asset_risk_calculation(alert_db):
    asset = alert_db.query(Asset).first()
    # Add alerts to increase score
    for i in range(2):
        alert_db.add(Alert(
            title=f"Critical Alert {i}",
            description="Compromise",
            rule_id="RULE-005",
            rule_name="Compromise",
            severity="CRITICAL",
            status="OPEN",
            affected_asset=asset.hostname
        ))
    alert_db.commit()

    score, level, factors = calculate_asset_risk(asset, alert_db)
    assert score > 20.0
    assert "asset_criticality" in factors
    assert "alert_threats" in factors
    assert factors["alert_threats"]["total_associated_alerts"] == 2

