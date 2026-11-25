"""
Live Attack Simulator Routes for MiniSIEM X
Generates synthetic, controlled attack scenarios passing through the exact same
ingestion, normalization, and detection pipeline.
Scenarios:
1. normal (legitimate authentication events)
2. brute_force (6 password guessing attempts)
3. suspicious_login (login from untrusted external IP)
4. port_scan (15 distinct ports probed from external scanner)
5. privilege_escalation (sudo root shell elevation)
6. account_compromise (failed logins -> success -> privilege elevation)
"""
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, List

from backend.database import get_db
from backend.models import LogEvent, Alert, Incident, IncidentEvent, LogSource
from backend.schemas import SimulationRequest, SimulationResponse
from backend.processors.normalizer import EventNormalizer
from backend.detection.engine import DetectionEngine

router = APIRouter(prefix="/api/simulation", tags=["Simulation"])

@router.post("/start", response_model=SimulationResponse)
def start_simulation(req: SimulationRequest, db: Session = Depends(get_db)):
    """Runs a controlled synthetic security simulation through the live detection engine."""
    scenario = req.scenario.lower().strip()
    now = datetime.now(timezone.utc)
    engine = DetectionEngine(db)

    events_to_ingest: List[Dict[str, Any]] = []

    if scenario == "normal":
        # Realistic internal traffic
        events_to_ingest = [
            {
                "timestamp": now - timedelta(seconds=15),
                "source": "linux",
                "hostname": "web-gateway-01.prod",
                "event_type": "auth_success",
                "username": "sysadmin",
                "source_ip": "10.0.0.1",
                "destination_ip": "192.168.1.100",
                "destination_port": 22,
                "severity": "INFO",
                "raw_event": "sshd[5412]: Accepted publickey for sysadmin from 10.0.0.1 port 52140 ssh2",
                "is_demo": True
            },
            {
                "timestamp": now - timedelta(seconds=5),
                "source": "web",
                "hostname": "api.minisiemx.local",
                "event_type": "auth_success",
                "username": "sarah.finance",
                "source_ip": "192.168.1.10",
                "destination_ip": "192.168.1.105",
                "destination_port": 443,
                "severity": "INFO",
                "raw_event": '192.168.1.10 - sarah.finance "POST /api/auth/login HTTP/1.1" 200 450',
                "is_demo": True
            }
        ]

    elif scenario == "brute_force":
        # 6 rapid failed logins from same external IP
        attacker_ip = "198.51.100.24"
        for i in range(6):
            events_to_ingest.append({
                "timestamp": now - timedelta(seconds=60 - (i * 8)),
                "source": "linux",
                "hostname": "web-gateway-01.prod",
                "event_type": "auth_failure",
                "username": "admin",
                "source_ip": attacker_ip,
                "destination_ip": "192.168.1.100",
                "destination_port": 22,
                "severity": "HIGH",
                "raw_event": f"sshd[{1024 + i}]: Failed password for invalid user admin from {attacker_ip} port {45210 + i} ssh2",
                "is_demo": True
            })

    elif scenario == "suspicious_login":
        # Login from an untrusted foreign IP (e.g., 203.0.113.88)
        untrusted_ip = "203.0.113.88"
        events_to_ingest = [
            {
                "timestamp": now,
                "source": "web",
                "hostname": "web-gateway-01.prod",
                "event_type": "auth_success",
                "username": "david.dev",
                "source_ip": untrusted_ip,
                "destination_ip": "192.168.1.100",
                "destination_port": 443,
                "severity": "INFO",
                "raw_event": f'{untrusted_ip} - david.dev "POST /api/v1/auth/login HTTP/1.1" 200 612',
                "is_demo": True
            }
        ]

    elif scenario == "port_scan":
        # 14 distinct ports probed within 30s
        scanner_ip = "198.51.100.99"
        target_ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 443, 445, 1433, 3306, 3389, 8080]
        for i, port in enumerate(target_ports):
            events_to_ingest.append({
                "timestamp": now - timedelta(seconds=30 - (i * 2)),
                "source": "simulated",
                "hostname": "web-gateway-01.prod",
                "event_type": "port_scan",
                "username": None,
                "source_ip": scanner_ip,
                "destination_ip": "192.168.1.100",
                "destination_port": port,
                "severity": "MEDIUM",
                "raw_event": f"TCP SYN probe received from {scanner_ip}:54321 to 192.168.1.100:{port}",
                "is_demo": True
            })

    elif scenario == "privilege_escalation":
        # Sudo elevation to root
        events_to_ingest = [
            {
                "timestamp": now,
                "source": "linux",
                "hostname": "web-gateway-01.prod",
                "event_type": "privilege_escalation",
                "username": "localuser",
                "source_ip": "192.168.1.45",
                "destination_ip": "192.168.1.100",
                "destination_port": 22,
                "severity": "HIGH",
                "raw_event": "sudo: localuser : TTY=pts/2 ; PWD=/home/localuser ; USER=root ; COMMAND=/bin/bash",
                "metadata": {"elevated_user": "root", "command": "/bin/bash"},
                "is_demo": True
            }
        ]

    elif scenario == "account_compromise":
        # Correlation attack story: 4 failed attempts -> 1 successful login -> 1 sudo privilege escalation
        attacker_ip = "198.51.100.77"
        target_user = "svc_deploy"

        # Step 1: Failed passwords
        for i in range(4):
            events_to_ingest.append({
                "timestamp": now - timedelta(seconds=120 - (i * 15)),
                "source": "linux",
                "hostname": "dc01.corp.minisiemx.local",
                "event_type": "auth_failure",
                "username": target_user,
                "source_ip": attacker_ip,
                "destination_ip": "10.0.0.1",
                "destination_port": 22,
                "severity": "HIGH",
                "raw_event": f"sshd[{8000 + i}]: Failed password for {target_user} from {attacker_ip} port {50000 + i}",
                "is_demo": True
            })

        # Step 2: Successful password guess
        events_to_ingest.append({
            "timestamp": now - timedelta(seconds=30),
            "source": "linux",
            "hostname": "dc01.corp.minisiemx.local",
            "event_type": "auth_success",
            "username": target_user,
            "source_ip": attacker_ip,
            "destination_ip": "10.0.0.1",
            "destination_port": 22,
            "severity": "INFO",
            "raw_event": f"sshd[8020]: Accepted password for {target_user} from {attacker_ip} port 50020 ssh2",
            "is_demo": True
        })

        # Step 3: Privilege elevation to root
        events_to_ingest.append({
            "timestamp": now - timedelta(seconds=10),
            "source": "linux",
            "hostname": "dc01.corp.minisiemx.local",
            "event_type": "privilege_escalation",
            "username": target_user,
            "source_ip": attacker_ip,
            "destination_ip": "10.0.0.1",
            "destination_port": 22,
            "severity": "HIGH",
            "raw_event": f"sudo: {target_user} : TTY=pts/0 ; USER=root ; COMMAND=/bin/bash",
            "metadata": {"elevated_user": "root", "command": "/bin/bash"},
            "is_demo": True
        })

    else:
        raise HTTPException(status_code=400, detail=f"Unknown scenario '{scenario}'. Supported: normal, brute_force, suspicious_login, port_scan, privilege_escalation, account_compromise")

    initial_alerts = db.query(Alert).count()
    initial_incidents = db.query(Incident).count()

    # Ingest and execute real detection pipeline
    for raw in events_to_ingest:
        norm = EventNormalizer.normalize(raw, default_source=raw.get("source", "simulated"), is_demo=True)
        log_entry = LogEvent(
            timestamp=norm["timestamp"],
            source=norm["source"],
            hostname=norm["hostname"],
            event_type=norm["event_type"],
            username=norm["username"],
            source_ip=norm["source_ip"],
            destination_ip=norm["destination_ip"],
            destination_port=norm["destination_port"],
            severity=norm["severity"],
            raw_event=norm["raw_event"],
            metadata_json=norm["metadata_json"],
            is_demo=True
        )
        db.add(log_entry)
        db.commit()
        db.refresh(log_entry)

        engine.process_event(log_entry)

    # Update demo source stats
    demo_source = db.query(LogSource).filter(LogSource.source_type == "DEMO").first()
    if demo_source:
        demo_source.last_event_at = datetime.now(timezone.utc)
        demo_source.total_events += len(events_to_ingest)
        db.commit()

    alerts_gen = db.query(Alert).count() - initial_alerts
    incidents_gen = db.query(Incident).count() - initial_incidents

    return {
        "status": "COMPLETED",
        "scenario": scenario,
        "events_generated": len(events_to_ingest),
        "alerts_generated": max(0, alerts_gen),
        "incidents_generated": max(0, incidents_gen),
        "details": f"Successfully injected {len(events_to_ingest)} synthetic events and executed live detection pipeline."
    }

@router.post("/reset")
def reset_simulation_data(db: Session = Depends(get_db)):
    """Deletes all demo/simulated logs, alerts, and incidents, restoring the clean baseline."""
    # Delete demo incident events
    demo_incidents = db.query(Incident).filter(Incident.is_demo == True).all()
    for inc in demo_incidents:
        db.query(IncidentEvent).filter(IncidentEvent.incident_id == inc.id).delete()
        db.delete(inc)

    # Delete demo alerts
    db.query(Alert).filter(Alert.is_demo == True).delete()

    # Delete demo logs
    deleted_logs = db.query(LogEvent).filter(LogEvent.is_demo == True).delete()

    # Reset demo source counters
    demo_src = db.query(LogSource).filter(LogSource.source_type == "DEMO").first()
    if demo_src:
        demo_src.total_events = 0
        demo_src.error_count = 0

    db.commit()
    return {
        "status": "SUCCESS",
        "message": f"Demo data purged cleanly. Removed {deleted_logs} simulated event records."
    }

