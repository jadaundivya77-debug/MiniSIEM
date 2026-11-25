"""
Windows Event Log Collector for MiniSIEM X
Parses Windows Security Events: Event ID 4624 (Logon Success), 4625 (Logon Failure),
4672 (Special Privileges Assigned), and 4720 (User Created).
"""
import re
from typing import List, Dict, Any
from backend.collectors.base_collector import BaseCollector

class WindowsCollector(BaseCollector):
    def __init__(self):
        super().__init__(name="Windows Collector", source_type="WINDOWS")

    def collect(self, raw_input: Any) -> List[Dict[str, Any]]:
        """Parses Windows event logs provided as dictionaries, JSON, or text blocks."""
        events: List[Dict[str, Any]] = []
        if isinstance(raw_input, list):
            for item in raw_input:
                if isinstance(item, dict):
                    events.append(self._parse_dict(item))
                elif isinstance(item, str):
                    events.append(self._parse_text(item))
        elif isinstance(raw_input, dict):
            events.append(self._parse_dict(raw_input))
        elif isinstance(raw_input, str):
            for block in raw_input.split("\n\n"):
                if block.strip():
                    events.append(self._parse_text(block.strip()))

        return [e for e in events if e]

    def _parse_dict(self, data: Dict[str, Any]) -> Dict[str, Any]:
        event_id = str(data.get("EventID") or data.get("event_id") or "")
        username = data.get("TargetUserName") or data.get("username") or data.get("AccountName")
        source_ip = data.get("IpAddress") or data.get("source_ip") or data.get("WorkstationName")
        dest_port = data.get("IpPort") or data.get("destination_port")
        hostname = data.get("Computer") or data.get("hostname")

        event_type = "windows_security_event"
        severity = "INFO"

        if event_id == "4625" or str(data.get("event_type")).lower() in ["auth_failure", "logon_failure"]:
            event_type = "auth_failure"
            severity = "HIGH"
        elif event_id == "4624" or str(data.get("event_type")).lower() in ["auth_success", "logon_success"]:
            event_type = "auth_success"
            severity = "INFO"
        elif event_id == "4672" or "privilege" in str(data.get("event_type")).lower():
            event_type = "privilege_escalation"
            severity = "HIGH"
        elif event_id == "4720":
            event_type = "account_created"
            severity = "MEDIUM"

        return {
            "source": "windows",
            "hostname": hostname,
            "event_type": event_type,
            "username": username,
            "source_ip": source_ip if source_ip != "-" else None,
            "destination_port": int(dest_port) if dest_port and str(dest_port).isdigit() else None,
            "severity": severity,
            "raw_event": str(data),
            "metadata": {"EventID": event_id, **data}
        }

    def _parse_text(self, text: str) -> Dict[str, Any]:
        event_id_match = re.search(r"Event ID:\s*(\d+)", text, re.IGNORECASE)
        user_match = re.search(r"Account Name:\s*(\S+)", text, re.IGNORECASE)
        ip_match = re.search(r"Source Network Address:\s*(\S+)", text, re.IGNORECASE)

        event_id = event_id_match.group(1) if event_id_match else "4624"
        username = user_match.group(1) if user_match else None
        source_ip = ip_match.group(1) if ip_match else None

        if source_ip == "-":
            source_ip = None

        event_type = "windows_security_event"
        severity = "INFO"
        if event_id == "4625":
            event_type = "auth_failure"
            severity = "HIGH"
        elif event_id == "4672":
            event_type = "privilege_escalation"
            severity = "HIGH"

        return {
            "source": "windows",
            "event_type": event_type,
            "username": username,
            "source_ip": source_ip,
            "severity": severity,
            "raw_event": text,
            "metadata": {"EventID": event_id}
        }

