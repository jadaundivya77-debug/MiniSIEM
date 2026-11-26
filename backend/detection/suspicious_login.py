"""
Rule 2: Suspicious Login Detection
Condition: Login from an IP not present in the configured trusted-IP list.
Severity: MEDIUM
MITRE: T1078
"""
from typing import Dict, Any, Optional, Set
from sqlalchemy.orm import Session
from backend.models import LogEvent, TrustedIP, DetectionRule
from backend.utils.helpers import safe_json_loads

class SuspiciousLoginDetector:
    RULE_ID = "RULE-002"

    @classmethod
    def check(cls, current_event: LogEvent, db: Session, rule_config: Optional[DetectionRule] = None) -> Optional[Dict[str, Any]]:
        """
        Flags successful login attempts originating from untrusted/unknown IPs.
        Skips local console / loopback / unspecified IPs to avoid false alerts on normal host logins.
        """
        if current_event.event_type != "auth_success" or not current_event.source_ip:
            return None

        src_ip = current_event.source_ip.strip()
        if src_ip in ["-", "", "127.0.0.1", "::1", "0.0.0.0", "localhost"]:
            return None

        # Skip non-network Windows logons (e.g., interactive/unlock/service) even if loopback-mapped
        meta = safe_json_loads(current_event.metadata_json)
        if current_event.source == "windows" and str(meta.get("LogonType", "")) in {"0", "2", "4", "5", "7"}:
            return None

        # Fetch trusted IP set
        trusted_ips: Set[str] = {
            t.ip_address for t in db.query(TrustedIP).filter(TrustedIP.is_active == True).all()
        }

        # If IP is in trusted set, not suspicious
        if src_ip in trusted_ips:
            return None

        return {
            "rule_id": cls.RULE_ID,
            "rule_name": "Suspicious Login from Untrusted IP",
            "severity": "MEDIUM",
            "title": f"Untrusted IP Login: Account '{current_event.username or 'unknown'}' accessed from {current_event.source_ip}",
            "source_ip": current_event.source_ip,
            "target_username": current_event.username,
            "affected_asset": current_event.hostname or current_event.destination_ip or "Corporate Asset",
            "event_count": 1,
            "time_window_seconds": 60,
            "mitre_id": "T1078",
            "mitre_name": "Valid Accounts",
            "mitre_tactic": "Initial Access",
            "matched_event_ids": [current_event.id],
            "evidence": {
                "source_ip": current_event.source_ip,
                "username": current_event.username,
                "auth_status": "success",
                "timestamp": current_event.timestamp.isoformat(),
                "trusted_whitelist_checked": True,
                "is_whitelisted": False
            }
        }

