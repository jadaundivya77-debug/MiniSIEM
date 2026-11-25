"""
Threat Intelligence & Trusted IP Management Routes for MiniSIEM X
Lookup IP reputation, manage internal trusted IP whitelists, and inspect threat tags.
"""
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from typing import List, Dict, Any

from backend.database import get_db
from backend.models import TrustedIP, Alert, LogEvent
from backend.schemas import TrustedIPResponse, TrustedIPCreate
from backend.utils.helpers import is_valid_ip

router = APIRouter(prefix="/api/threat-intel", tags=["Threat Intelligence"])

# Local reputation database of known threat categories for simulation
LOCAL_THREAT_REPUTATION: Dict[str, Dict[str, Any]] = {
    "198.51.100.24": {
        "reputation": "MALICIOUS",
        "threat_score": 92,
        "category": "SSH Brute-Force Botnet",
        "country": "Anonymous / Proxy",
        "asn": "AS12345 Suspicious Hosting",
        "description": "Known automated password-guessing node targeting enterprise SSH gateways."
    },
    "198.51.100.99": {
        "reputation": "SUSPICIOUS",
        "threat_score": 78,
        "category": "Mass Port Scanner",
        "country": "Anonymous",
        "asn": "AS9999 Scanner Network",
        "description": "Observed performing horizontal service scans across port 22, 443, 3389."
    },
    "203.0.113.88": {
        "reputation": "UNTRUSTED",
        "threat_score": 45,
        "category": "Unverified Public IP",
        "country": "External Public",
        "asn": "AS4500 Commercial ISP",
        "description": "Residential broadband IP. Not in corporate whitelist."
    },
    "198.51.100.77": {
        "reputation": "MALICIOUS",
        "threat_score": 96,
        "category": "Credential Stuffing & C2",
        "country": "Proxy / VPN",
        "asn": "AS54321 Threat Actor Cluster",
        "description": "Flagged for correlated account takeovers and lateral movement."
    }
}

@router.get("/lookup/{ip}")
def lookup_ip_intelligence(ip: str, db: Session = Depends(get_db)):
    """Looks up reputation, threat score, whitelist status, and historical alerts for an IP."""
    clean_ip = ip.strip()
    if not is_valid_ip(clean_ip):
        raise HTTPException(status_code=400, detail="Invalid IP address format")

    # Check whitelist
    trusted_entry = db.query(TrustedIP).filter(TrustedIP.ip_address == clean_ip, TrustedIP.is_active == True).first()
    is_trusted = trusted_entry is not None

    # Check local intelligence dataset
    intel = LOCAL_THREAT_REPUTATION.get(clean_ip, {
        "reputation": "BENIGN / UNKNOWN",
        "threat_score": 10 if not is_trusted else 0,
        "category": "General IP",
        "country": "Internal / Unclassified",
        "asn": "N/A",
        "description": "No prior malicious threat intelligence records matched."
    })

    # Query local alert history for this IP
    alerts = db.query(Alert).filter(Alert.source_ip == clean_ip).order_by(Alert.created_at.desc()).limit(10).all()
    events_count = db.query(LogEvent).filter(LogEvent.source_ip == clean_ip).count()

    return {
        "ip": clean_ip,
        "is_trusted": is_trusted,
        "trusted_details": trusted_entry.description if trusted_entry else None,
        "intelligence": intel,
        "local_history": {
            "total_events_observed": events_count,
            "total_alerts_triggered": len(alerts),
            "recent_alerts": [
                {"id": a.id, "title": a.title, "severity": a.severity, "rule_id": a.rule_id, "time": a.created_at.isoformat()}
                for a in alerts
            ]
        }
    }

@router.get("/trusted-ips", response_model=List[TrustedIPResponse])
def get_trusted_ips(db: Session = Depends(get_db)):
    """Returns list of whitelisted internal/trusted IP addresses."""
    return db.query(TrustedIP).filter(TrustedIP.is_active == True).order_by(TrustedIP.created_at.desc()).all()

@router.post("/trusted-ips", response_model=TrustedIPResponse)
def add_trusted_ip(data: TrustedIPCreate, db: Session = Depends(get_db)):
    """Adds an IP address to the whitelist."""
    if not is_valid_ip(data.ip_address):
        raise HTTPException(status_code=400, detail="Invalid IP address format")

    existing = db.query(TrustedIP).filter(TrustedIP.ip_address == data.ip_address).first()
    if existing:
        existing.is_active = True
        existing.description = data.description or existing.description
        db.commit()
        db.refresh(existing)
        return existing

    new_ip = TrustedIP(
        ip_address=data.ip_address,
        description=data.description or "Analyst Whitelisted IP",
        added_by="Security Analyst",
        is_active=True
    )
    db.add(new_ip)
    db.commit()
    db.refresh(new_ip)
    return new_ip

@router.delete("/trusted-ips/{id}")
def remove_trusted_ip(id: int, db: Session = Depends(get_db)):
    """Removes an IP address from the whitelist."""
    entry = db.query(TrustedIP).filter(TrustedIP.id == id).first()
    if not entry:
        raise HTTPException(status_code=404, detail="Trusted IP entry not found")
    db.delete(entry)
    db.commit()
    return {"status": "success", "message": f"IP {entry.ip_address} removed from whitelist"}

