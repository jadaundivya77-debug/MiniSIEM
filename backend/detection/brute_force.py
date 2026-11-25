"""
Rule 1: Brute-Force Login Detection
Condition: >= 5 failed login attempts from same source IP and username within 120 seconds.
Severity: HIGH
MITRE: T1110
"""
from datetime import datetime, timedelta, timezone
from typing import List, Dict, Any, Optional
from sqlalchemy.orm import Session
from backend.models import LogEvent, DetectionRule

class BruteForceDetector:
    RULE_ID = "RULE-001"

    @classmethod
    def check(cls, current_event: LogEvent, db: Session, rule_config: Optional[DetectionRule] = None) -> Optional[Dict[str, Any]]:
        """
        Evaluates whether the incoming event triggers a Brute Force detection.
        Requires:
        - event_type == 'auth_failure'
        - source_ip and username present
        """
        if current_event.event_type != "auth_failure" or not current_event.source_ip or not current_event.username:
            return None

        # Configurable thresholds
        threshold = rule_config.threshold_count if rule_config else 5
        window_seconds = rule_config.time_window_seconds if rule_config else 120

        cutoff = current_event.timestamp - timedelta(seconds=window_seconds)

        # Query recent failed logins matching this IP and username
        failures = db.query(LogEvent).filter(
            LogEvent.event_type == "auth_failure",
            LogEvent.source_ip == current_event.source_ip,
            LogEvent.username == current_event.username,
            LogEvent.timestamp >= cutoff,
            LogEvent.timestamp <= current_event.timestamp
        ).order_by(LogEvent.timestamp.asc()).all()

        count = len(failures)
        if count >= threshold:
            event_ids = [e.id for e in failures]
            timestamps = [e.timestamp.isoformat() for e in failures]

            return {
                "rule_id": cls.RULE_ID,
                "rule_name": "Brute-Force Login Detection",
                "severity": "HIGH",
                "title": f"Brute-Force Authentication Attack on '{current_event.username}'",
                "source_ip": current_event.source_ip,
                "target_username": current_event.username,
                "affected_asset": current_event.hostname or current_event.destination_ip or "Target Host",
                "event_count": count,
                "time_window_seconds": window_seconds,
                "mitre_id": "T1110",
                "mitre_name": "Brute Force: Password Guessing",
                "mitre_tactic": "Credential Access",
                "matched_event_ids": event_ids,
                "evidence": {
                    "failed_attempts": count,
                    "threshold": threshold,
                    "window_seconds": window_seconds,
                    "source_ip": current_event.source_ip,
                    "username": current_event.username,
                    "timestamps": timestamps
                }
            }

        return None

