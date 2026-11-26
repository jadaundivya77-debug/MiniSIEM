"""
Rule 4: Privilege Escalation Detection
Condition: Detect privilege-change or elevation events (sudo to root, Windows 4672, sensitive privilege assignment).
Severity: HIGH
MITRE: T1548
"""
from typing import Dict, Any, Optional
from sqlalchemy.orm import Session
from backend.models import LogEvent, DetectionRule
from backend.utils.helpers import safe_json_loads
from backend.collectors.windows_collector import is_noisy_system_account

class PrivilegeEscalationDetector:
    RULE_ID = "RULE-004"

    @classmethod
    def check(cls, current_event: LogEvent, db: Session, rule_config: Optional[DetectionRule] = None) -> Optional[Dict[str, Any]]:
        """
        Detects unauthorized or suspicious privilege escalation attempts.
        Filters out built-in Windows OS service/machine accounts (SYSTEM, DWM-*, UMFD-*, *$)
        to prevent false alerts on normal Windows background activity.
        """
        if current_event.source == "windows" and is_noisy_system_account(current_event.username):
            return None

        is_elevated = False
        reason = ""

        # Check event_type
        if current_event.event_type in ["privilege_escalation", "sudo", "privilege_change"]:
            is_elevated = True
            reason = "Privilege elevation event flagged by log collector."

        # Check metadata
        meta = safe_json_loads(current_event.metadata_json)
        if str(meta.get("EventID", "")) == "4672":
            is_elevated = True
            privs = meta.get("PrivilegeList")
            if privs:
                reason = f"Windows Security Event 4672: Special privileges assigned ({privs})."
            else:
                reason = "Windows Security Event 4672: Special privileges assigned to new logon."
        elif meta.get("elevated_user") == "root":
            is_elevated = True
            cmd = meta.get("command", "")
            reason = f"Linux sudo elevation executed: command '{cmd}' as root."

        if is_elevated:
            return {
                "rule_id": cls.RULE_ID,
                "rule_name": "Privilege Escalation / Sudo Elevation",
                "severity": "HIGH",
                "title": f"Privilege Elevation by User '{current_event.username or 'unknown'}' on {current_event.hostname or 'Host'}",
                "source_ip": current_event.source_ip,
                "target_username": current_event.username,
                "affected_asset": current_event.hostname or current_event.destination_ip or "Target Host",
                "event_count": 1,
                "time_window_seconds": 60,
                "mitre_id": "T1548",
                "mitre_name": "Abuse Elevation Control Mechanism: Sudo and Sudoers",
                "mitre_tactic": "Privilege Escalation",
                "matched_event_ids": [current_event.id],
                "evidence": {
                    "username": current_event.username,
                    "hostname": current_event.hostname,
                    "source_ip": current_event.source_ip,
                    "raw_event": current_event.raw_event,
                    "metadata": meta,
                    "detection_reason": reason
                }
            }

        return None

