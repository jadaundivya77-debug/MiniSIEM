import json
from datetime import datetime, timezone
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, Session
from backend.config import DATABASE_URL, DEFAULT_TRUSTED_IPS
from backend.models import (
    Base, User, DetectionRule, TrustedIP, Asset, LogSource, LogEvent, Alert, Incident
)
from backend.utils.security import hash_password

# Database Engine setup
connect_args = {"check_same_thread": False} if "sqlite" in DATABASE_URL else {}
engine = create_engine(DATABASE_URL, connect_args=connect_args)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

def get_db():
    """FastAPI database session dependency."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def init_db():
    """Initializes schema and seeds baseline rules, users, assets and log sources."""
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        # 1. Seed Default Users if none exist
        if db.query(User).count() == 0:
            default_users = [
                User(
                    username="admin",
                    email="admin@minisiemx.local",
                    hashed_password=hash_password("Admin@MiniSIEM2026!"),
                    full_name="SOC Super Administrator",
                    role="SUPER_ADMIN",
                    is_active=True
                ),
                User(
                    username="secadmin",
                    email="secadmin@minisiemx.local",
                    hashed_password=hash_password("SecAdmin@2026!"),
                    full_name="Lead Security Architect",
                    role="SECURITY_ADMIN",
                    is_active=True
                ),
                User(
                    username="analyst",
                    email="analyst@minisiemx.local",
                    hashed_password=hash_password("Analyst@2026!"),
                    full_name="Tier-2 SOC Analyst",
                    role="SECURITY_ANALYST",
                    is_active=True
                ),
                User(
                    username="viewer",
                    email="viewer@minisiemx.local",
                    hashed_password=hash_password("Viewer@2026!"),
                    full_name="Compliance Auditor",
                    role="VIEWER",
                    is_active=True
                )
            ]
            db.add_all(default_users)
            db.commit()

        # 2. Seed Default Detection Rules
        if db.query(DetectionRule).count() == 0:
            default_rules = [
                DetectionRule(
                    rule_id="RULE-001",
                    name="Brute-Force Login Detection",
                    description="Detects repeated authentication failures targeting the same username or from the same source IP within a sliding window.",
                    category="AUTH",
                    severity="HIGH",
                    is_enabled=True,
                    time_window_seconds=120,
                    threshold_count=5,
                    parameters_json=json.dumps({"failed_threshold": 5, "window_seconds": 120}),
                    mitre_id="T1110",
                    mitre_name="Brute Force: Password Guessing",
                    mitre_tactic="Credential Access"
                ),
                DetectionRule(
                    rule_id="RULE-002",
                    name="Suspicious Login from Untrusted IP",
                    description="Flags successful or attempted logins originating from external or non-whitelisted IP addresses.",
                    category="AUTH",
                    severity="MEDIUM",
                    is_enabled=True,
                    time_window_seconds=60,
                    threshold_count=1,
                    parameters_json=json.dumps({"check_whitelist": True}),
                    mitre_id="T1078",
                    mitre_name="Valid Accounts",
                    mitre_tactic="Initial Access"
                ),
                DetectionRule(
                    rule_id="RULE-003",
                    name="Port Scanning Reconnaissance",
                    description="Identifies connection attempts to multiple distinct destination ports from a single source IP in a short duration.",
                    category="NETWORK",
                    severity="MEDIUM",
                    is_enabled=True,
                    time_window_seconds=60,
                    threshold_count=10,
                    parameters_json=json.dumps({"port_count_threshold": 10, "window_seconds": 60}),
                    mitre_id="T1046",
                    mitre_name="Network Service Discovery",
                    mitre_tactic="Discovery"
                ),
                DetectionRule(
                    rule_id="RULE-004",
                    name="Privilege Escalation / Sudo Elevation",
                    description="Detects execution of administrative elevation commands, sudo abuse, or assignment of sensitive Windows security privileges.",
                    category="PRIVILEGE",
                    severity="HIGH",
                    is_enabled=True,
                    time_window_seconds=60,
                    threshold_count=1,
                    parameters_json=json.dumps({"track_sudo": True, "track_special_privs": True}),
                    mitre_id="T1548",
                    mitre_name="Abuse Elevation Control Mechanism: Sudo and Sudoers",
                    mitre_tactic="Privilege Escalation"
                ),
                DetectionRule(
                    rule_id="RULE-005",
                    name="Account Compromise Correlation",
                    description="Correlates repeated failed authentication attempts immediately followed by a successful login and subsequent privileged activity.",
                    category="CORRELATION",
                    severity="CRITICAL",
                    is_enabled=True,
                    time_window_seconds=300,
                    threshold_count=1,
                    parameters_json=json.dumps({"failed_min": 3, "window_seconds": 300}),
                    mitre_id="T1078",
                    mitre_name="Valid Accounts - Correlated Compromise",
                    mitre_tactic="Initial Access & Persistence"
                )
            ]
            db.add_all(default_rules)
            db.commit()

        # 3. Seed Default Trusted IPs
        if db.query(TrustedIP).count() == 0:
            for ip in DEFAULT_TRUSTED_IPS:
                db.add(TrustedIP(ip_address=ip, description="Default Internal / Loopback Network", added_by="System Initializer"))
            db.commit()

        # 4. Seed Default Assets
        if db.query(Asset).count() == 0:
            default_assets = [
                Asset(
                    name="Corporate Domain Controller",
                    hostname="dc01.corp.minisiemx.local",
                    ip_address="10.0.0.1",
                    os_type="Windows Server 2022",
                    asset_type="SERVER",
                    criticality="CRITICAL",
                    last_event_at=datetime.now(timezone.utc),
                    risk_score=15.0,
                    risk_level="LOW",
                    risk_factors_json=json.dumps({"baseline": "High criticality asset with low alert baseline"})
                ),
                Asset(
                    name="Production Web Application Gateway",
                    hostname="web-gateway-01.prod",
                    ip_address="192.168.1.100",
                    os_type="Linux Ubuntu 22.04 LTS",
                    asset_type="WEB_SERVER",
                    criticality="HIGH",
                    last_event_at=datetime.now(timezone.utc),
                    risk_score=20.0,
                    risk_level="LOW",
                    risk_factors_json=json.dumps({"baseline": "Public-facing application gateway"})
                ),
                Asset(
                    name="Internal Database Cluster",
                    hostname="db-primary.internal",
                    ip_address="10.0.0.50",
                    os_type="Debian GNU/Linux 12",
                    asset_type="DATABASE",
                    criticality="CRITICAL",
                    last_event_at=datetime.now(timezone.utc),
                    risk_score=10.0,
                    risk_level="LOW",
                    risk_factors_json=json.dumps({"baseline": "Restricted internal database tier"})
                ),
                Asset(
                    name="Finance Workstation 04",
                    hostname="fin-ws-04.corp",
                    ip_address="10.0.1.45",
                    os_type="Windows 11 Enterprise",
                    asset_type="WORKSTATION",
                    criticality="MEDIUM",
                    last_event_at=datetime.now(timezone.utc),
                    risk_score=5.0,
                    risk_level="LOW",
                    risk_factors_json=json.dumps({"baseline": "Standard employee endpoint"})
                )
            ]
            db.add_all(default_assets)
            db.commit()

        # 5. Seed Baseline Log Sources
        if db.query(LogSource).count() == 0:
            sources = [
                LogSource(
                    name="Linux Host Auth Collector",
                    source_type="LINUX",
                    hostname="web-gateway-01.prod",
                    ip_address="192.168.1.100",
                    status="CONNECTED",
                    last_event_at=datetime.now(timezone.utc),
                    total_events=0
                ),
                LogSource(
                    name="Windows Event Log Forwarder",
                    source_type="WINDOWS",
                    hostname="dc01.corp.minisiemx.local",
                    ip_address="10.0.0.1",
                    status="CONNECTED",
                    last_event_at=datetime.now(timezone.utc),
                    total_events=0
                ),
                LogSource(
                    name="Web Application Access Stream",
                    source_type="WEB",
                    hostname="api.minisiemx.local",
                    ip_address="192.168.1.105",
                    status="CONNECTED",
                    last_event_at=datetime.now(timezone.utc),
                    total_events=0
                ),
                LogSource(
                    name="Simulated Attack Generator",
                    source_type="DEMO",
                    hostname="sim-sandbox.minisiemx.local",
                    ip_address="198.51.100.24",
                    status="DEMO",
                    last_event_at=datetime.now(timezone.utc),
                    total_events=0
                )
            ]
            db.add_all(sources)
            db.commit()

    finally:
        db.close()

