"""
Central Threat Detection Engine for MiniSIEM X
Executes detection rules, manages cooldowns & deduplication, links evidence,
generates explainable security alerts, and correlates multi-stage attack incidents.
"""
from datetime import datetime, timedelta, timezone
from typing import List, Dict, Any, Optional
from sqlalchemy.orm import Session

from backend.config import ALERT_COOLDOWN_SECONDS
from backend.models import LogEvent, Alert, Incident, IncidentEvent, DetectionRule, Asset
from backend.detection.brute_force import BruteForceDetector
from backend.detection.suspicious_login import SuspiciousLoginDetector
from backend.detection.port_scan import PortScanDetector
from backend.detection.privilege_escalation import PrivilegeEscalationDetector
from backend.detection.event_correlation import EventCorrelator
from backend.utils.helpers import safe_json_dumps

class DetectionEngine:
    def __init__(self, db: Session):
        self.db = db
        self._load_rules()

    def _load_rules(self):
        """Loads enabled rules and configurations from database."""
        rules = self.db.query(DetectionRule).all()
        self.rules_by_id = {r.rule_id: r for r in rules}

    def process_event(self, event: LogEvent) -> List[Alert]:
        """
        Runs the full detection pipeline on a single newly normalized LogEvent.
        Returns a list of created or updated Alert models.
        """
        self._load_rules()
        created_alerts: List[Alert] = []

        # 1. Rule 1: Brute Force
        r1 = self.rules_by_id.get(BruteForceDetector.RULE_ID)
        if r1 and r1.is_enabled:
            detection_res = BruteForceDetector.check(event, self.db, r1)
            if detection_res:
                alert = self._handle_detection(detection_res, is_demo=event.is_demo)
                if alert:
                    created_alerts.append(alert)

        # 2. Rule 2: Suspicious Login
        r2 = self.rules_by_id.get(SuspiciousLoginDetector.RULE_ID)
        if r2 and r2.is_enabled:
            detection_res = SuspiciousLoginDetector.check(event, self.db, r2)
            if detection_res:
                alert = self._handle_detection(detection_res, is_demo=event.is_demo)
                if alert:
                    created_alerts.append(alert)

        # 3. Rule 3: Port Scan
        r3 = self.rules_by_id.get(PortScanDetector.RULE_ID)
        if r3 and r3.is_enabled:
            detection_res = PortScanDetector.check(event, self.db, r3)
            if detection_res:
                alert = self._handle_detection(detection_res, is_demo=event.is_demo)
                if alert:
                    created_alerts.append(alert)

        # 4. Rule 4: Privilege Escalation
        r4 = self.rules_by_id.get(PrivilegeEscalationDetector.RULE_ID)
        if r4 and r4.is_enabled:
            detection_res = PrivilegeEscalationDetector.check(event, self.db, r4)
            if detection_res:
                alert = self._handle_detection(detection_res, is_demo=event.is_demo)
                if alert:
                    created_alerts.append(alert)

        # 5. Rule 5: Account Compromise Correlation (Generates Incident + Alert)
        r5 = self.rules_by_id.get(EventCorrelator.RULE_ID)
        if r5 and r5.is_enabled:
            correlation_res = EventCorrelator.check_compromise_chain(event, self.db, r5)
            if correlation_res:
                alert = self._handle_detection(correlation_res, is_demo=event.is_demo)
                if alert:
                    created_alerts.append(alert)
                    self._create_or_update_correlated_incident(correlation_res, alert, event)

        return created_alerts

    def _handle_detection(self, d_data: Dict[str, Any], is_demo: bool = False) -> Optional[Alert]:
        """
        Suppresses duplicates within cooldown period; otherwise generates a new Alert.
        """
        cooldown_cutoff = datetime.now(timezone.utc) - timedelta(seconds=ALERT_COOLDOWN_SECONDS)

        # Deduplication check for OPEN alerts matching rule, IP, and username
        existing_alert = self.db.query(Alert).filter(
            Alert.rule_id == d_data["rule_id"],
            Alert.source_ip == d_data["source_ip"],
            Alert.target_username == d_data["target_username"],
            Alert.status == "OPEN",
            Alert.created_at >= cooldown_cutoff
        ).first()

        if existing_alert:
            # Update existing alert event count and timestamp
            existing_alert.event_count += 1
            existing_alert.updated_at = datetime.now(timezone.utc)
            self.db.commit()
            return existing_alert

        # Lazy import of explanation generator to prevent circular dependencies
        from backend.services.explanation_service import generate_alert_explanation, get_investigation_recommendations

        explanation = generate_alert_explanation(d_data)
        recommended_actions = get_investigation_recommendations(d_data["rule_id"])

        new_alert = Alert(
            title=d_data["title"],
            description=f"Automated detection triggered by {d_data['rule_name']}",
            rule_id=d_data["rule_id"],
            rule_name=d_data["rule_name"],
            severity=d_data["severity"],
            status="OPEN",
            source_ip=d_data["source_ip"],
            target_username=d_data["target_username"],
            affected_asset=d_data["affected_asset"],
            event_count=d_data["event_count"],
            time_window_seconds=d_data["time_window_seconds"],
            explanation=explanation,
            recommended_actions=recommended_actions,
            raw_evidence_json=safe_json_dumps(d_data.get("evidence", {})),
            mitre_technique_id=d_data.get("mitre_id"),
            mitre_technique_name=d_data.get("mitre_name"),
            mitre_tactic=d_data.get("mitre_tactic"),
            is_demo=is_demo,
            created_at=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc)
        )
        self.db.add(new_alert)
        self.db.commit()
        self.db.refresh(new_alert)

        # Trigger asset risk update if affected_asset matches
        self._update_asset_alert_count(new_alert.affected_asset)

        return new_alert

    def _create_or_update_correlated_incident(self, c_data: Dict[str, Any], alert: Alert, trigger_event: LogEvent):
        """Creates a high-visibility correlated incident and links the attack story."""
        # Check if an open incident for this compromise already exists
        existing_inc = self.db.query(Incident).filter(
            Incident.title.like(f"%{c_data['target_username']}%"),
            Incident.status == "OPEN"
        ).first()

        if existing_inc:
            existing_inc.attack_story = c_data.get("attack_story", existing_inc.attack_story)
            existing_inc.updated_at = datetime.now(timezone.utc)
            # Link current alert
            self.db.add(IncidentEvent(
                incident_id=existing_inc.id,
                log_event_id=trigger_event.id,
                alert_id=alert.id,
                stage="Attack Progression",
                note=f"Correlated activity observed for user {c_data['target_username']}"
            ))
            self.db.commit()
            return existing_inc

        # Generate incident number
        incident_count = self.db.query(Incident).count() + 1
        inc_number = f"INC-2026-{incident_count:04d}"

        new_incident = Incident(
            incident_number=inc_number,
            title=f"Account Takeover & Compromise: {c_data['target_username']} ({c_data['source_ip']})",
            description=f"Correlated multi-stage attack detected: Password brute-forcing followed by successful login session from IP {c_data['source_ip']}.",
            severity="CRITICAL",
            status="OPEN",
            assigned_analyst="Unassigned (Tier-1 SOC Pool)",
            investigation_notes="Automated correlation created by MiniSIEM X Detection Engine. Immediate credential revocation and host isolation recommended.",
            root_cause="Credential Guessing / Brute Force Authentication",
            attack_story=c_data.get("attack_story", ""),
            mitre_tactic="Initial Access & Persistence",
            is_demo=trigger_event.is_demo,
            created_at=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc)
        )
        self.db.add(new_incident)
        self.db.commit()
        self.db.refresh(new_incident)

        # Attach matched events into the IncidentEvent timeline
        order = 0
        for ev_id in c_data.get("matched_event_ids", []):
            order += 1
            self.db.add(IncidentEvent(
                incident_id=new_incident.id,
                log_event_id=ev_id,
                alert_id=alert.id if order == 1 else None,
                stage="Attack Story Event",
                note=f"Chronological event record #{order}",
                order_index=order
            ))

        self.db.commit()
        return new_incident

    def _update_asset_alert_count(self, asset_identifier: Optional[str]):
        """Increments associated alert count on the matching asset and triggers risk score recalculation."""
        if not asset_identifier:
            return
        asset = self.db.query(Asset).filter(
            (Asset.name.ilike(f"%{asset_identifier}%")) |
            (Asset.hostname.ilike(f"%{asset_identifier}%")) |
            (Asset.ip_address == asset_identifier)
        ).first()

        if asset:
            asset.associated_alerts_count += 1
            # Recalculate risk score via risk_service
            from backend.services.risk_service import calculate_asset_risk
            risk_score, risk_level, risk_factors = calculate_asset_risk(asset, self.db)
            asset.risk_score = risk_score
            asset.risk_level = risk_level
            asset.risk_factors_json = safe_json_dumps(risk_factors)
            asset.last_event_at = datetime.now(timezone.utc)
            self.db.commit()

