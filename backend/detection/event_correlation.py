"""
Rule 5: Account Compromise Correlation Engine
Condition: Repeated failed login attempts followed by a successful login from the same IP and username,
optionally followed by privilege escalation, within a configurable sliding window (default 300s).
Severity: CRITICAL
MITRE: T1078, T1110, T1548
"""
from datetime import datetime, timedelta, timezone
from typing import Dict, Any, Optional, List
from sqlalchemy.orm import Session
from backend.models import LogEvent, Alert, Incident, IncidentEvent, DetectionRule
from backend.utils.helpers import safe_json_dumps

class EventCorrelator:
    RULE_ID = "RULE-005"

    @classmethod
    def check_compromise_chain(
        cls, 
        current_event: LogEvent, 
        db: Session, 
        rule_config: Optional[DetectionRule] = None
    ) -> Optional[Dict[str, Any]]:
        """
        When a successful login occurs, checks if it was preceded by multiple failed
        logins from the same source IP and username (or same hostname and username when
        source_ip is missing for local Windows logons).
        Generates a unified CRITICAL incident.
        """
        # Trigger on successful authentication
        if current_event.event_type != "auth_success" or not current_event.username:
            return None
        if not current_event.source_ip and not current_event.hostname:
            return None

        window_seconds = rule_config.time_window_seconds if rule_config else 300
        cutoff = current_event.timestamp - timedelta(seconds=window_seconds)

        # 1. Look for prior failed login attempts
        failure_query = db.query(LogEvent).filter(
            LogEvent.event_type == "auth_failure",
            LogEvent.username == current_event.username,
            LogEvent.timestamp >= cutoff,
            LogEvent.timestamp <= current_event.timestamp
        )
        if current_event.source_ip:
            failure_query = failure_query.filter(LogEvent.source_ip == current_event.source_ip)
        else:
            failure_query = failure_query.filter(
                LogEvent.source_ip.is_(None),
                LogEvent.hostname == current_event.hostname
            )
        prior_failures = failure_query.order_by(LogEvent.timestamp.asc()).all()

        if len(prior_failures) < 3:
            return None # Insufficient prior failures to assert correlation

        # 2. Check for co-occurring or subsequent privilege escalation
        subsequent_priv_events = db.query(LogEvent).filter(
            LogEvent.event_type.in_(["privilege_escalation", "sudo"]),
            LogEvent.username == current_event.username,
            LogEvent.timestamp >= current_event.timestamp - timedelta(seconds=5),
            LogEvent.timestamp <= current_event.timestamp + timedelta(seconds=180)
        ).order_by(LogEvent.timestamp.asc()).all()

        origin_label = current_event.source_ip or f"Local Host ({current_event.hostname})"

        # Build chronological attack story timeline
        timeline_events: List[Dict[str, Any]] = []

        # Step 1: Failed Logins
        timeline_events.append({
            "stage": "Reconnaissance / Credential Access",
            "time": prior_failures[0].timestamp.isoformat(),
            "description": f"Observed {len(prior_failures)} failed authentication attempts from {origin_label} against user '{current_event.username}'",
            "log_id": prior_failures[0].id
        })

        # Step 2: Successful Login
        timeline_events.append({
            "stage": "Initial Access / Compromise",
            "time": current_event.timestamp.isoformat(),
            "description": f"Successful authentication gained for user '{current_event.username}' from {origin_label}",
            "log_id": current_event.id
        })

        # Step 3: Privilege Escalation (if detected)
        for priv in subsequent_priv_events:
            timeline_events.append({
                "stage": "Privilege Escalation",
                "time": priv.timestamp.isoformat(),
                "description": f"Elevated privileges observed for user '{current_event.username}' on {priv.hostname or 'host'}",
                "log_id": priv.id
            })

        matched_event_ids = [e.id for e in prior_failures] + [current_event.id] + [e.id for e in subsequent_priv_events]

        # Chronological narrative text
        story_narrative = (
            f"At {prior_failures[0].timestamp.strftime('%H:%M:%S UTC')}, {origin_label} "
            f"initiated {len(prior_failures)} credential guessing attempts targeting account '{current_event.username}'. "
            f"At {current_event.timestamp.strftime('%H:%M:%S UTC')}, a successful login was established for the same account. "
        )
        if subsequent_priv_events:
            story_narrative += (
                f"Alongside or immediately following initial access, administrative privilege escalation was triggered, "
                f"demonstrating complete host compromise."
            )
        else:
            story_narrative += (
                f"The sequence of password brute-forcing immediately followed by valid session establishment strongly indicates account compromise."
            )

        return {
            "rule_id": cls.RULE_ID,
            "rule_name": "Account Compromise Correlation",
            "severity": "CRITICAL",
            "title": f"CRITICAL: Confirmed Account Compromise for '{current_event.username}' ({origin_label})",
            "source_ip": current_event.source_ip,
            "target_username": current_event.username,
            "affected_asset": current_event.hostname or current_event.destination_ip or "Internal Host",
            "event_count": len(matched_event_ids),
            "time_window_seconds": window_seconds,
            "mitre_id": "T1078",
            "mitre_name": "Valid Accounts - Correlated Compromise",
            "mitre_tactic": "Initial Access & Persistence",
            "matched_event_ids": matched_event_ids,
            "timeline": timeline_events,
            "attack_story": story_narrative,
            "evidence": {
                "failed_count": len(prior_failures),
                "successful_login_time": current_event.timestamp.isoformat(),
                "source_ip": current_event.source_ip,
                "origin": origin_label,
                "username": current_event.username,
                "has_privilege_escalation": len(subsequent_priv_events) > 0,
                "timeline": timeline_events
            }
        }

