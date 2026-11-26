import json
from datetime import datetime, timedelta, timezone
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from backend.collectors.windows_collector import WindowsCollector
from backend.database import init_db
from backend.detection.brute_force import BruteForceDetector
from backend.detection.engine import DetectionEngine
from backend.detection.event_correlation import EventCorrelator
from backend.detection.privilege_escalation import PrivilegeEscalationDetector
from backend.detection.suspicious_login import SuspiciousLoginDetector
from backend.models import Alert, Base, DetectionRule, Incident, IncidentEvent, LogEvent, TrustedIP
from backend.processors.normalizer import EventNormalizer


SAMPLE_WEVTUTIL_XML = """<Events>
  <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
    <System>
      <EventID>4625</EventID>
      <EventRecordID>1001</EventRecordID>
      <TimeCreated SystemTime="2026-11-26T01:00:00.0000000Z"/>
      <Computer>LAPTOP-DEMO</Computer>
    </System>
    <EventData>
      <Data Name="TargetUserName">hackdemo</Data>
      <Data Name="TargetDomainName">LAPTOP-DEMO</Data>
      <Data Name="LogonType">2</Data>
      <Data Name="IpAddress">-</Data>
      <Data Name="IpPort">-</Data>
      <Data Name="WorkstationName">LAPTOP-DEMO</Data>
    </EventData>
  </Event>
  <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
    <System>
      <EventID>4624</EventID>
      <EventRecordID>1002</EventRecordID>
      <TimeCreated SystemTime="2026-11-26T01:00:10.0000000Z"/>
      <Computer>LAPTOP-DEMO</Computer>
    </System>
    <EventData>
      <Data Name="TargetUserName">Victus</Data>
      <Data Name="LogonType">2</Data>
      <Data Name="IpAddress">127.0.0.1</Data>
    </EventData>
  </Event>
  <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
    <System>
      <EventID>4672</EventID>
      <EventRecordID>1003</EventRecordID>
      <TimeCreated SystemTime="2026-11-26T01:00:11.0000000Z"/>
      <Computer>LAPTOP-DEMO</Computer>
    </System>
    <EventData>
      <Data Name="SubjectUserName">Victus</Data>
      <Data Name="SubjectDomainName">LAPTOP-DEMO</Data>
      <Data Name="PrivilegeList">SeDebugPrivilege SeImpersonatePrivilege</Data>
    </EventData>
  </Event>
  <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
    <System>
      <EventID>4672</EventID>
      <EventRecordID>1004</EventRecordID>
      <TimeCreated SystemTime="2026-11-26T01:00:12.0000000Z"/>
      <Computer>LAPTOP-DEMO</Computer>
    </System>
    <EventData>
      <Data Name="SubjectUserName">SYSTEM</Data>
      <Data Name="PrivilegeList">SeAssignPrimaryTokenPrivilege</Data>
    </EventData>
  </Event>
</Events>"""


def _make_memory_db():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(bind=engine)
    Session = sessionmaker(bind=engine)
    db = Session()
    db.add_all([
        DetectionRule(rule_id="RULE-001", name="Brute-Force", description="BF", category="AUTH", severity="HIGH", is_enabled=True, time_window_seconds=120, threshold_count=5),
        DetectionRule(rule_id="RULE-002", name="Suspicious Login", description="SL", category="AUTH", severity="MEDIUM", is_enabled=True, time_window_seconds=60, threshold_count=1),
        DetectionRule(rule_id="RULE-004", name="Privilege Escalation", description="PE", category="PRIVILEGE", severity="HIGH", is_enabled=True, time_window_seconds=60, threshold_count=1),
        DetectionRule(rule_id="RULE-005", name="Account Compromise", description="AC", category="CORRELATION", severity="CRITICAL", is_enabled=True, time_window_seconds=300, threshold_count=1),
        TrustedIP(ip_address="10.0.0.1", description="Internal"),
    ])
    db.commit()
    return db


def test_windows_xml_parsing_and_noise_filter():
    collector = WindowsCollector()
    events = collector.parse_windows_xml(SAMPLE_WEVTUTIL_XML, include_system=False)

    # SYSTEM 4672 should be filtered out, leaving 4625, 4624, 4672 (Victus)
    assert len(events) == 3

    ev_fail, ev_ok, ev_priv = events
    assert ev_fail["event_type"] == "auth_failure"
    assert ev_fail["username"] == "hackdemo"
    assert ev_fail["source_ip"] is None
    assert ev_fail["is_demo"] is False

    assert ev_ok["event_type"] == "auth_success"
    assert ev_ok["username"] == "Victus"
    assert ev_ok["source_ip"] == "127.0.0.1"

    assert ev_priv["event_type"] == "privilege_escalation"
    assert ev_priv["username"] == "Victus"
    assert ev_priv["metadata"]["EventID"] == "4672"


def test_missing_ip_brute_force_scoped_by_hostname():
    db = _make_memory_db()
    now = datetime.now(timezone.utc)
    rule1 = db.query(DetectionRule).filter(DetectionRule.rule_id == "RULE-001").first()

    # 3 failures on HOST-A and 2 failures on HOST-B with missing IP for same username must NOT merge
    for i in range(3):
        db.add(LogEvent(timestamp=now - timedelta(seconds=20 - i), source="windows", hostname="HOST-A", event_type="auth_failure", username="alice", source_ip=None, severity="HIGH"))
    for i in range(2):
        ev_b = LogEvent(timestamp=now - timedelta(seconds=10 - i), source="windows", hostname="HOST-B", event_type="auth_failure", username="alice", source_ip=None, severity="HIGH")
        db.add(ev_b)
    db.commit()

    assert BruteForceDetector.check(ev_b, db, rule1) is None

    # 2 more failures on HOST-A (total 5 on HOST-A) SHOULD trigger
    db.add(LogEvent(timestamp=now - timedelta(seconds=2), source="windows", hostname="HOST-A", event_type="auth_failure", username="alice", source_ip=None, severity="HIGH"))
    fifth_a = LogEvent(timestamp=now, source="windows", hostname="HOST-A", event_type="auth_failure", username="alice", source_ip=None, severity="HIGH")
    db.add(fifth_a)
    db.commit()

    det = BruteForceDetector.check(fifth_a, db, rule1)
    assert det is not None
    assert det["event_count"] == 5
    assert det["affected_asset"] == "HOST-A"
    db.close()


def test_windows_noise_suppression_and_real_4672_and_local_compromise():
    db = _make_memory_db()
    engine = DetectionEngine(db)
    now = datetime.now(timezone.utc)

    # 1. SYSTEM 4672 should NOT alert
    sys_priv = LogEvent(
        timestamp=now, source="windows", hostname="LAPTOP-DEMO",
        event_type="privilege_escalation", username="SYSTEM", severity="HIGH",
        metadata_json=json.dumps({"EventID": "4672"})
    )
    db.add(sys_priv)
    db.commit()
    assert engine.process_event(sys_priv) == []

    # 2. Local 4624 from 127.0.0.1 should NOT trigger Suspicious Login (RULE-002)
    local_ok = LogEvent(
        timestamp=now, source="windows", hostname="LAPTOP-DEMO",
        event_type="auth_success", username="Victus", source_ip="127.0.0.1", severity="INFO",
        metadata_json=json.dumps({"EventID": "4624", "LogonType": "2"})
    )
    db.add(local_ok)
    db.commit()
    assert engine.process_event(local_ok) == []

    # 3. Real user 4672 SHOULD trigger RULE-004
    user_priv = LogEvent(
        timestamp=now, source="windows", hostname="LAPTOP-DEMO",
        event_type="privilege_escalation", username="Victus", severity="HIGH",
        metadata_json=json.dumps({"EventID": 4672, "PrivilegeList": "SeDebugPrivilege"})
    )
    db.add(user_priv)
    db.commit()
    priv_alerts = engine.process_event(user_priv)
    assert any(a.rule_id == "RULE-004" for a in priv_alerts)

    # 4. Local compromise chain: 3 x 4625 (missing IP) + 4624 (missing IP) on same host & user -> RULE-005 + Incident
    for i in range(3):
        f_ev = LogEvent(
            timestamp=now + timedelta(seconds=10 + i),
            source="windows", hostname="LAPTOP-DEMO",
            event_type="auth_failure", username="demo_target", source_ip=None, severity="HIGH"
        )
        db.add(f_ev)
        db.commit()
        engine.process_event(f_ev)

    s_ev = LogEvent(
        timestamp=now + timedelta(seconds=20),
        source="windows", hostname="LAPTOP-DEMO",
        event_type="auth_success", username="demo_target", source_ip=None, severity="INFO"
    )
    db.add(s_ev)
    db.commit()
    corr_alerts = engine.process_event(s_ev)
    assert any(a.rule_id == "RULE-005" for a in corr_alerts)
    inc = db.query(Incident).filter(Incident.title.like("%demo_target%")).first()
    assert inc is not None
    assert db.query(IncidentEvent).filter(IncidentEvent.incident_id == inc.id).count() >= 4
    db.close()
