from datetime import datetime, timezone
from sqlalchemy import (
    Column, Integer, String, Text, Boolean, Float, DateTime, ForeignKey, Index
)
from sqlalchemy.orm import declarative_base, relationship

Base = declarative_base()

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    username = Column(String(50), unique=True, index=True, nullable=False)
    email = Column(String(100), unique=True, index=True, nullable=False)
    hashed_password = Column(String(255), nullable=False)
    full_name = Column(String(100), nullable=True)
    role = Column(String(30), default="SECURITY_ANALYST", nullable=False) # SUPER_ADMIN, SECURITY_ADMIN, SECURITY_ANALYST, VIEWER
    is_active = Column(Boolean, default=True, nullable=False)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)

class LogSource(Base):
    __tablename__ = "log_sources"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    name = Column(String(100), unique=True, nullable=False)
    source_type = Column(String(50), nullable=False) # LINUX, WINDOWS, WEB, API, FILE, DEMO
    hostname = Column(String(100), nullable=True)
    ip_address = Column(String(45), nullable=True)
    status = Column(String(30), default="DISCONNECTED", nullable=False) # CONNECTED, DISCONNECTED, STALE, STOPPED, ERROR, DEMO
    last_event_at = Column(DateTime, nullable=True)
    last_heartbeat_at = Column(DateTime, nullable=True)
    last_error = Column(Text, nullable=True)
    pending_events = Column(Integer, default=0, nullable=False)
    total_events = Column(Integer, default=0, nullable=False)
    error_count = Column(Integer, default=0, nullable=False)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    updated_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc), nullable=False)

class LogEvent(Base):
    __tablename__ = "logs"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    timestamp = Column(DateTime, nullable=False, index=True)
    source = Column(String(50), nullable=False, index=True) # linux, windows, web, simulated
    hostname = Column(String(100), nullable=True, index=True)
    event_type = Column(String(100), nullable=False, index=True) # auth_failure, auth_success, sudo, port_scan, etc.
    username = Column(String(100), nullable=True, index=True)
    source_ip = Column(String(45), nullable=True, index=True)
    destination_ip = Column(String(45), nullable=True, index=True)
    destination_port = Column(Integer, nullable=True)
    severity = Column(String(20), default="INFO", nullable=False, index=True) # INFO, LOW, MEDIUM, HIGH, CRITICAL
    raw_event = Column(Text, nullable=True)
    metadata_json = Column(Text, nullable=True) # Additional contextual attributes
    event_record_id = Column(Integer, nullable=True, index=True)
    origin_type = Column(String(40), nullable=True, index=True) # REAL_WINDOWS, SIMULATED, FILE_IMPORT, MANUAL_INGEST, INGESTED_API
    is_demo = Column(Boolean, default=False, nullable=False, index=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)

    __table_args__ = (
        Index("idx_logs_src_ip_time", "source_ip", "timestamp"),
        Index("idx_logs_user_time", "username", "timestamp"),
        Index("idx_logs_event_type_time", "event_type", "timestamp"),
    )

class Alert(Base):
    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    title = Column(String(200), nullable=False)
    description = Column(Text, nullable=False)
    rule_id = Column(String(50), nullable=False, index=True)
    rule_name = Column(String(150), nullable=False)
    severity = Column(String(20), nullable=False, index=True) # LOW, MEDIUM, HIGH, CRITICAL
    status = Column(String(30), default="OPEN", nullable=False, index=True) # OPEN, INVESTIGATING, RESOLVED, FALSE_POSITIVE
    source_ip = Column(String(45), nullable=True, index=True)
    target_username = Column(String(100), nullable=True, index=True)
    affected_asset = Column(String(100), nullable=True)
    event_count = Column(Integer, default=1, nullable=False)
    time_window_seconds = Column(Integer, default=120, nullable=False)
    explanation = Column(Text, nullable=True) # Detailed explainable text: What, Why, Next steps
    recommended_actions = Column(Text, nullable=True)
    raw_evidence_json = Column(Text, nullable=True)
    mitre_technique_id = Column(String(50), nullable=True)
    mitre_technique_name = Column(String(150), nullable=True)
    mitre_tactic = Column(String(100), nullable=True)
    origin_type = Column(String(40), nullable=True)
    is_demo = Column(Boolean, default=False, nullable=False)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False, index=True)
    updated_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc), nullable=False)
    resolved_at = Column(DateTime, nullable=True)
    resolved_by = Column(String(50), nullable=True)

class Incident(Base):
    __tablename__ = "incidents"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    incident_number = Column(String(50), unique=True, index=True, nullable=False) # e.g. INC-2026-0001
    title = Column(String(200), nullable=False)
    description = Column(Text, nullable=False)
    severity = Column(String(20), nullable=False, index=True) # LOW, MEDIUM, HIGH, CRITICAL
    status = Column(String(30), default="OPEN", nullable=False, index=True) # OPEN, INVESTIGATING, RESOLVED, FALSE_POSITIVE
    assigned_analyst = Column(String(100), nullable=True)
    investigation_notes = Column(Text, nullable=True)
    root_cause = Column(Text, nullable=True)
    attack_story = Column(Text, nullable=True) # Chronological narrative of the attack
    mitre_tactic = Column(String(100), nullable=True)
    origin_type = Column(String(40), nullable=True)
    is_demo = Column(Boolean, default=False, nullable=False)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False, index=True)
    updated_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc), nullable=False)
    resolved_at = Column(DateTime, nullable=True)
    resolved_by = Column(String(50), nullable=True)

    incident_events = relationship("IncidentEvent", back_populates="incident", cascade="all, delete-orphan")

class IncidentEvent(Base):
    __tablename__ = "incident_events"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    incident_id = Column(Integer, ForeignKey("incidents.id", ondelete="CASCADE"), nullable=False, index=True)
    log_event_id = Column(Integer, ForeignKey("logs.id", ondelete="SET NULL"), nullable=True)
    alert_id = Column(Integer, ForeignKey("alerts.id", ondelete="SET NULL"), nullable=True)
    stage = Column(String(100), nullable=True) # Reconnaissance, Initial Access, Privilege Escalation, etc.
    note = Column(Text, nullable=True)
    order_index = Column(Integer, default=0, nullable=False)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)

    incident = relationship("Incident", back_populates="incident_events")

class Asset(Base):
    __tablename__ = "assets"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    name = Column(String(100), unique=True, nullable=False)
    hostname = Column(String(100), index=True, nullable=False)
    ip_address = Column(String(45), index=True, nullable=False)
    os_type = Column(String(50), nullable=False) # Linux Ubuntu, Windows Server 2022, Debian, etc.
    asset_type = Column(String(50), nullable=False) # SERVER, WORKSTATION, DATABASE, WEB_SERVER, FIREWALL
    criticality = Column(String(20), default="MEDIUM", nullable=False) # LOW, MEDIUM, HIGH, CRITICAL
    last_event_at = Column(DateTime, nullable=True)
    associated_alerts_count = Column(Integer, default=0, nullable=False)
    risk_score = Column(Float, default=0.0, nullable=False) # 0.0 - 100.0
    risk_level = Column(String(20), default="LOW", nullable=False) # LOW, MEDIUM, HIGH, CRITICAL
    risk_factors_json = Column(Text, nullable=True) # Detailed calculation explanation
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    updated_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc), nullable=False)

class DetectionRule(Base):
    __tablename__ = "detection_rules"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    rule_id = Column(String(50), unique=True, index=True, nullable=False) # e.g. RULE-001
    name = Column(String(150), nullable=False)
    description = Column(Text, nullable=False)
    category = Column(String(50), nullable=False) # AUTH, NETWORK, PRIVILEGE, CORRELATION
    severity = Column(String(20), nullable=False) # LOW, MEDIUM, HIGH, CRITICAL
    is_enabled = Column(Boolean, default=True, nullable=False)
    time_window_seconds = Column(Integer, default=120, nullable=False)
    threshold_count = Column(Integer, default=5, nullable=False)
    parameters_json = Column(Text, nullable=True)
    mitre_id = Column(String(50), nullable=True)
    mitre_name = Column(String(150), nullable=True)
    mitre_tactic = Column(String(100), nullable=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    updated_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc), nullable=False)

class TrustedIP(Base):
    __tablename__ = "trusted_ips"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    ip_address = Column(String(45), unique=True, index=True, nullable=False)
    description = Column(String(200), nullable=True)
    added_by = Column(String(50), default="System", nullable=False)
    is_active = Column(Boolean, default=True, nullable=False)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)

class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    user_id = Column(Integer, nullable=True)
    username = Column(String(50), nullable=False)
    action = Column(String(100), nullable=False) # LOGIN, LOGOUT, UPDATE_INCIDENT, UPDATE_RULE, etc.
    resource_type = Column(String(50), nullable=True)
    resource_id = Column(String(50), nullable=True)
    details = Column(Text, nullable=True)
    ip_address = Column(String(45), nullable=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False, index=True)

