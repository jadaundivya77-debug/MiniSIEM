from datetime import datetime
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field

# ----------------- AUTH SCHEMAS -----------------
class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user: Dict[str, Any]

class TokenData(BaseModel):
    username: Optional[str] = None
    role: Optional[str] = None

class UserLogin(BaseModel):
    username: str
    password: str

class UserCreate(BaseModel):
    username: str
    email: str
    password: str
    full_name: Optional[str] = None
    role: str = "SECURITY_ANALYST"

class UserResponse(BaseModel):
    id: int
    username: str
    email: str
    full_name: Optional[str] = None
    role: str
    is_active: bool
    created_at: datetime
    model_config = {"from_attributes": True}

# ----------------- LOG SCHEMAS -----------------
class LogEventCreate(BaseModel):
    timestamp: Optional[str | datetime] = None
    source: str = "custom"
    hostname: Optional[str] = None
    event_type: str
    username: Optional[str] = None
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    destination_port: Optional[int] = None
    severity: str = "INFO"
    raw_event: Optional[str] = None
    metadata: Optional[Dict[str, Any]] = None
    is_demo: bool = False

class LogEventResponse(BaseModel):
    id: int
    timestamp: datetime
    source: str
    hostname: Optional[str] = None
    event_type: str
    username: Optional[str] = None
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    destination_port: Optional[int] = None
    severity: str
    raw_event: Optional[str] = None
    metadata_json: Optional[str] = None
    is_demo: bool
    created_at: datetime
    model_config = {"from_attributes": True}

class LogBatchRequest(BaseModel):
    events: List[LogEventCreate]
    source_name: Optional[str] = None

class LogUploadResponse(BaseModel):
    total_received: int
    total_ingested: int
    total_errors: int
    errors: List[str] = []
    source: str
    sample_preview: List[Dict[str, Any]] = []

# ----------------- ALERT SCHEMAS -----------------
class AlertResponse(BaseModel):
    id: int
    title: str
    description: str
    rule_id: str
    rule_name: str
    severity: str
    status: str
    source_ip: Optional[str] = None
    target_username: Optional[str] = None
    affected_asset: Optional[str] = None
    event_count: int
    time_window_seconds: int
    explanation: Optional[str] = None
    recommended_actions: Optional[str] = None
    raw_evidence_json: Optional[str] = None
    mitre_technique_id: Optional[str] = None
    mitre_technique_name: Optional[str] = None
    mitre_tactic: Optional[str] = None
    is_demo: bool
    created_at: datetime
    updated_at: datetime
    resolved_at: Optional[datetime] = None
    resolved_by: Optional[str] = None
    model_config = {"from_attributes": True}

class AlertUpdate(BaseModel):
    status: str # OPEN, INVESTIGATING, RESOLVED, FALSE_POSITIVE
    notes: Optional[str] = None

# ----------------- INCIDENT SCHEMAS -----------------
class IncidentEventResponse(BaseModel):
    id: int
    incident_id: int
    log_event_id: Optional[int] = None
    alert_id: Optional[int] = None
    stage: Optional[str] = None
    note: Optional[str] = None
    order_index: int
    created_at: datetime
    log_event: Optional[LogEventResponse] = None
    alert: Optional[AlertResponse] = None
    model_config = {"from_attributes": True}

class IncidentCreate(BaseModel):
    title: str
    description: str
    severity: str = "HIGH"
    assigned_analyst: Optional[str] = None
    investigation_notes: Optional[str] = None
    related_alert_ids: List[int] = []
    related_log_ids: List[int] = []

class IncidentUpdate(BaseModel):
    title: Optional[str] = None
    description: Optional[str] = None
    severity: Optional[str] = None
    status: Optional[str] = None # OPEN, INVESTIGATING, RESOLVED, FALSE_POSITIVE
    assigned_analyst: Optional[str] = None
    investigation_notes: Optional[str] = None
    root_cause: Optional[str] = None

class IncidentResponse(BaseModel):
    id: int
    incident_number: str
    title: str
    description: str
    severity: str
    status: str
    assigned_analyst: Optional[str] = None
    investigation_notes: Optional[str] = None
    root_cause: Optional[str] = None
    attack_story: Optional[str] = None
    mitre_tactic: Optional[str] = None
    is_demo: bool
    created_at: datetime
    updated_at: datetime
    resolved_at: Optional[datetime] = None
    resolved_by: Optional[str] = None
    events_count: Optional[int] = 0
    model_config = {"from_attributes": True}

# ----------------- LOG SOURCE SCHEMAS -----------------
class LogSourceCreate(BaseModel):
    name: str
    source_type: str # LINUX, WINDOWS, WEB, API, FILE, DEMO
    hostname: Optional[str] = None
    ip_address: Optional[str] = None

class LogSourceResponse(BaseModel):
    id: int
    name: str
    source_type: str
    hostname: Optional[str] = None
    ip_address: Optional[str] = None
    status: str # CONNECTED, DISCONNECTED, STALE, DEMO
    last_event_at: Optional[datetime] = None
    total_events: int
    error_count: int
    created_at: datetime
    updated_at: datetime
    model_config = {"from_attributes": True}

# ----------------- ASSET SCHEMAS -----------------
class AssetCreate(BaseModel):
    name: str
    hostname: str
    ip_address: str
    os_type: str
    asset_type: str = "SERVER"
    criticality: str = "MEDIUM"

class AssetResponse(BaseModel):
    id: int
    name: str
    hostname: str
    ip_address: str
    os_type: str
    asset_type: str
    criticality: str
    last_event_at: Optional[datetime] = None
    associated_alerts_count: int
    risk_score: float
    risk_level: str
    risk_factors_json: Optional[str] = None
    created_at: datetime
    updated_at: datetime
    model_config = {"from_attributes": True}

# ----------------- DETECTION RULE SCHEMAS -----------------
class DetectionRuleResponse(BaseModel):
    id: int
    rule_id: str
    name: str
    description: str
    category: str
    severity: str
    is_enabled: bool
    time_window_seconds: int
    threshold_count: int
    parameters_json: Optional[str] = None
    mitre_id: Optional[str] = None
    mitre_name: Optional[str] = None
    mitre_tactic: Optional[str] = None
    created_at: datetime
    updated_at: datetime
    model_config = {"from_attributes": True}

class DetectionRuleUpdate(BaseModel):
    is_enabled: Optional[bool] = None
    time_window_seconds: Optional[int] = None
    threshold_count: Optional[int] = None
    severity: Optional[str] = None

# ----------------- TRUSTED IP SCHEMAS -----------------
class TrustedIPCreate(BaseModel):
    ip_address: str
    description: Optional[str] = None

class TrustedIPResponse(BaseModel):
    id: int
    ip_address: str
    description: Optional[str] = None
    added_by: str
    is_active: bool
    created_at: datetime
    model_config = {"from_attributes": True}

# ----------------- DASHBOARD SCHEMAS -----------------
class DashboardStatsResponse(BaseModel):
    total_events: int
    total_alerts: int
    critical_incidents: int
    active_sources: int
    open_incidents: int
    events_processed_today: int
    is_demo: bool
    alerts_by_severity: Dict[str, int]
    incidents_by_status: Dict[str, int]
    top_attack_types: List[Dict[str, Any]]
    events_by_source: List[Dict[str, Any]]
    top_suspicious_ips: List[Dict[str, Any]]
    top_risky_assets: List[Dict[str, Any]]
    detection_engine_status: Dict[str, Any]

# ----------------- AI ASSISTANT SCHEMAS -----------------
class AssistantMessage(BaseModel):
    message: str
    context_type: Optional[str] = None # incident, alert, event, general
    context_id: Optional[str | int] = None

class AssistantResponse(BaseModel):
    reply: str
    verified_evidence: List[str] = []
    rule_conclusions: List[str] = []
    ai_recommendations: List[str] = []
    timestamp: str

# ----------------- SIMULATION SCHEMAS -----------------
class SimulationRequest(BaseModel):
    scenario: str # normal, brute_force, suspicious_login, port_scan, privilege_escalation, account_compromise
    repeat_count: int = 1

class SimulationResponse(BaseModel):
    status: str
    scenario: str
    events_generated: int
    alerts_generated: int
    incidents_generated: int
    details: str
