"""
Rule 3: Port Scanning Detection
Condition: >= 10 unique destination ports targeted from same source IP within 60 seconds.
Severity: MEDIUM
MITRE: T1046
"""
from datetime import timedelta
from typing import Dict, Any, Optional
from sqlalchemy.orm import Session
from sqlalchemy import func
from backend.models import LogEvent, DetectionRule

class PortScanDetector:
    RULE_ID = "RULE-003"

    @classmethod
    def check(cls, current_event: LogEvent, db: Session, rule_config: Optional[DetectionRule] = None) -> Optional[Dict[str, Any]]:
        """
        Detects port scanning reconnaissance targeting multiple destination ports.
        """
        if not current_event.source_ip or current_event.destination_port is None:
            return None

        threshold = rule_config.threshold_count if rule_config else 10
        window_seconds = rule_config.time_window_seconds if rule_config else 60

        cutoff = current_event.timestamp - timedelta(seconds=window_seconds)

        # Query events from this source IP with destination ports
        events_in_window = db.query(LogEvent).filter(
            LogEvent.source_ip == current_event.source_ip,
            LogEvent.destination_port != None,
            LogEvent.timestamp >= cutoff,
            LogEvent.timestamp <= current_event.timestamp
        ).all()

        unique_ports = {e.destination_port for e in events_in_window if e.destination_port}
        if len(unique_ports) >= threshold:
            event_ids = [e.id for e in events_in_window]
            sorted_ports = sorted(list(unique_ports))

            return {
                "rule_id": cls.RULE_ID,
                "rule_name": "Port Scanning Reconnaissance",
                "severity": "MEDIUM",
                "title": f"Network Port Scan Detected from {current_event.source_ip} ({len(unique_ports)} Ports)",
                "source_ip": current_event.source_ip,
                "target_username": None,
                "affected_asset": current_event.hostname or current_event.destination_ip or "Network Perimeter",
                "event_count": len(events_in_window),
                "time_window_seconds": window_seconds,
                "mitre_id": "T1046",
                "mitre_name": "Network Service Discovery",
                "mitre_tactic": "Discovery",
                "matched_event_ids": event_ids,
                "evidence": {
                    "source_ip": current_event.source_ip,
                    "unique_ports_scanned": sorted_ports[:50],
                    "total_ports_count": len(unique_ports),
                    "threshold": threshold,
                    "window_seconds": window_seconds
                }
            }

        return None

