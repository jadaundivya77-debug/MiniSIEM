import pytest
from datetime import datetime, timezone, timedelta
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from backend.models import Base, LogEvent, DetectionRule, TrustedIP
from backend.detection.brute_force import BruteForceDetector
from backend.detection.suspicious_login import SuspiciousLoginDetector
from backend.detection.port_scan import PortScanDetector
from backend.detection.privilege_escalation import PrivilegeEscalationDetector
from backend.detection.event_correlation import EventCorrelator

@pytest.fixture
def test_db():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(bind=engine)
    Session = sessionmaker(bind=engine)
    session = Session()

    # Seed test rules
    r1 = DetectionRule(
        rule_id="RULE-001", name="Brute-Force Detection", description="Detects password guessing", category="AUTH",
        severity="HIGH", is_enabled=True, time_window_seconds=120, threshold_count=5
    )
    r2 = DetectionRule(
        rule_id="RULE-002", name="Suspicious Login", description="Detects untrusted IP logins", category="AUTH",
        severity="MEDIUM", is_enabled=True, time_window_seconds=60, threshold_count=1
    )
    r3 = DetectionRule(
        rule_id="RULE-003", name="Port Scan", description="Detects network sweeps", category="NETWORK",
        severity="MEDIUM", is_enabled=True, time_window_seconds=60, threshold_count=10
    )
    r4 = DetectionRule(
        rule_id="RULE-004", name="Privilege Escalation", description="Detects sudo/admin elevation", category="PRIVILEGE",
        severity="HIGH", is_enabled=True, time_window_seconds=60, threshold_count=1
    )
    r5 = DetectionRule(
        rule_id="RULE-005", name="Account Compromise", description="Correlates failed to successful logins", category="CORRELATION",
        severity="CRITICAL", is_enabled=True, time_window_seconds=300, threshold_count=1
    )
    t_ip = TrustedIP(ip_address="10.0.0.1", description="Internal Trusted Host")

    session.add_all([r1, r2, r3, r4, r5, t_ip])
    session.commit()

    yield session
    session.close()

def test_brute_force_detection(test_db):
    now = datetime.now(timezone.utc)
    ip = "198.51.100.24"
    user = "admin"

    # Inject 4 failed attempts
    for i in range(4):
        test_db.add(LogEvent(
            timestamp=now - timedelta(seconds=40 - (i * 5)),
            source="linux", event_type="auth_failure",
            username=user, source_ip=ip, severity="HIGH"
        ))
    test_db.commit()

    # 5th attempt (triggers threshold of 5)
    fifth_event = LogEvent(
        timestamp=now, source="linux", event_type="auth_failure",
        username=user, source_ip=ip, severity="HIGH"
    )
    test_db.add(fifth_event)
    test_db.commit()

    rule1 = test_db.query(DetectionRule).filter(DetectionRule.rule_id == "RULE-001").first()
    detection = BruteForceDetector.check(fifth_event, test_db, rule1)

    assert detection is not None
    assert detection["rule_id"] == "RULE-001"
    assert detection["severity"] == "HIGH"
    assert detection["event_count"] == 5

def test_suspicious_login_detection(test_db):
    now = datetime.now(timezone.utc)
    # Login from trusted IP should NOT trigger
    trusted_event = LogEvent(
        timestamp=now, source="linux", event_type="auth_success",
        username="admin", source_ip="10.0.0.1", severity="INFO"
    )
    test_db.add(trusted_event)
    test_db.commit()
    rule2 = test_db.query(DetectionRule).filter(DetectionRule.rule_id == "RULE-002").first()
    assert SuspiciousLoginDetector.check(trusted_event, test_db, rule2) is None

    # Login from untrusted IP SHOULD trigger
    untrusted_event = LogEvent(
        timestamp=now, source="web", event_type="auth_success",
        username="admin", source_ip="203.0.113.88", severity="INFO"
    )
    test_db.add(untrusted_event)
    test_db.commit()
    det = SuspiciousLoginDetector.check(untrusted_event, test_db, rule2)
    assert det is not None
    assert det["rule_id"] == "RULE-002"
    assert det["source_ip"] == "203.0.113.88"

def test_port_scan_detection(test_db):
    now = datetime.now(timezone.utc)
    scanner_ip = "198.51.100.99"
    # Inject 11 distinct port probes
    for port in range(20, 31):
        test_db.add(LogEvent(
            timestamp=now - timedelta(seconds=20),
            source="simulated", event_type="port_scan",
            source_ip=scanner_ip, destination_port=port, severity="MEDIUM"
        ))
    test_db.commit()

    last_event = LogEvent(
        timestamp=now, source="simulated", event_type="port_scan",
        source_ip=scanner_ip, destination_port=80, severity="MEDIUM"
    )
    test_db.add(last_event)
    test_db.commit()

    rule3 = test_db.query(DetectionRule).filter(DetectionRule.rule_id == "RULE-003").first()
    det = PortScanDetector.check(last_event, test_db, rule3)
    assert det is not None
    assert det["rule_id"] == "RULE-003"
    assert det["evidence"]["total_ports_count"] >= 10

def test_privilege_escalation_detection(test_db):
    priv_event = LogEvent(
        timestamp=datetime.now(timezone.utc),
        source="linux", event_type="privilege_escalation",
        username="hacker", source_ip="192.168.1.50",
        severity="HIGH", raw_event="sudo /bin/bash as root"
    )
    test_db.add(priv_event)
    test_db.commit()

    rule4 = test_db.query(DetectionRule).filter(DetectionRule.rule_id == "RULE-004").first()
    det = PrivilegeEscalationDetector.check(priv_event, test_db, rule4)
    assert det is not None
    assert det["rule_id"] == "RULE-004"
    assert det["severity"] == "HIGH"

def test_account_compromise_correlation(test_db):
    now = datetime.now(timezone.utc)
    ip = "198.51.100.77"
    user = "victim_user"

    # 1. Prior failed logins
    for i in range(3):
        test_db.add(LogEvent(
            timestamp=now - timedelta(seconds=60 - (i * 10)),
            source="linux", event_type="auth_failure",
            username=user, source_ip=ip, severity="HIGH"
        ))
    test_db.commit()

    # 2. Subsequent successful login
    success_event = LogEvent(
        timestamp=now, source="linux", event_type="auth_success",
        username=user, source_ip=ip, severity="INFO"
    )
    test_db.add(success_event)
    test_db.commit()

    rule5 = test_db.query(DetectionRule).filter(DetectionRule.rule_id == "RULE-005").first()
    corr = EventCorrelator.check_compromise_chain(success_event, test_db, rule5)
    assert corr is not None
    assert corr["rule_id"] == "RULE-005"
    assert corr["severity"] == "CRITICAL"
    assert "Attack Narrative" in corr["attack_story"] or "initiated" in corr["attack_story"]
