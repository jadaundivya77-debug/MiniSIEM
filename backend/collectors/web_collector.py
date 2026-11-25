"""
Web Application Log Collector for MiniSIEM X
Parses web access logs, API access records, and web authentication events.
"""
import re
from typing import List, Dict, Any
from backend.collectors.base_collector import BaseCollector

class WebCollector(BaseCollector):
    def __init__(self):
        super().__init__(name="Web Collector", source_type="WEB")

    def collect(self, raw_input: Any) -> List[Dict[str, Any]]:
        """Parses web access lines or dictionaries."""
        events: List[Dict[str, Any]] = []
        if isinstance(raw_input, list):
            for item in raw_input:
                if isinstance(item, dict):
                    events.append(self._parse_dict(item))
                elif isinstance(item, str):
                    parsed = self._parse_line(item)
                    if parsed:
                        events.append(parsed)
        elif isinstance(raw_input, dict):
            events.append(self._parse_dict(raw_input))
        elif isinstance(raw_input, str):
            for line in raw_input.splitlines():
                parsed = self._parse_line(line)
                if parsed:
                    events.append(parsed)

        return events

    def _parse_dict(self, data: Dict[str, Any]) -> Dict[str, Any]:
        status_code = int(data.get("status_code", 200))
        endpoint = str(data.get("endpoint") or data.get("path") or "")
        method = str(data.get("method", "GET")).upper()
        source_ip = data.get("client_ip") or data.get("source_ip") or data.get("ip")
        username = data.get("username") or data.get("user")

        event_type = "web_access"
        severity = "INFO"

        if status_code == 401 or "/login" in endpoint and status_code >= 400:
            event_type = "auth_failure"
            severity = "HIGH"
        elif "/login" in endpoint and status_code == 200:
            event_type = "auth_success"
            severity = "INFO"
        elif "/admin" in endpoint or "/privilege" in endpoint:
            event_type = "privilege_access"
            severity = "MEDIUM"
        elif status_code == 403:
            event_type = "access_denied"
            severity = "MEDIUM"

        return {
            "source": "web",
            "event_type": event_type,
            "username": username,
            "source_ip": source_ip,
            "destination_port": int(data.get("destination_port", 443)),
            "severity": severity,
            "raw_event": str(data),
            "metadata": {"status_code": status_code, "endpoint": endpoint, "method": method}
        }

    def _parse_line(self, line: str) -> Dict[str, Any]:
        # Common Log Format (CLF) / Nginx / Apache
        # e.g.: 198.51.100.24 - admin [24/Nov/2026:10:15:30 +0000] "POST /api/auth/login HTTP/1.1" 401 128
        clf_match = re.search(
            r'^(\S+)\s+\S+\s+(\S+)\s+\[([^\]]+)\]\s+"(\S+)\s+(\S+)\s+[^"]+"\s+(\d{3})\s+(\d+|-)',
            line
        )
        if clf_match:
            source_ip = clf_match.group(1)
            raw_user = clf_match.group(2)
            username = None if raw_user == "-" else raw_user
            method = clf_match.group(4)
            endpoint = clf_match.group(5)
            status_code = int(clf_match.group(6))

            event_type = "web_access"
            severity = "INFO"
            if status_code == 401:
                event_type = "auth_failure"
                severity = "HIGH"
            elif "/login" in endpoint and status_code == 200:
                event_type = "auth_success"
                severity = "INFO"
            elif "/admin" in endpoint:
                event_type = "privilege_access"
                severity = "MEDIUM"
            elif status_code == 403:
                event_type = "access_denied"
                severity = "MEDIUM"

            return {
                "source": "web",
                "event_type": event_type,
                "username": username,
                "source_ip": source_ip,
                "destination_port": 443 if "https" in endpoint.lower() else 80,
                "severity": severity,
                "raw_event": line,
                "metadata": {"endpoint": endpoint, "method": method, "status_code": status_code}
            }

        return {
            "source": "web",
            "event_type": "web_access",
            "severity": "INFO",
            "raw_event": line
        }

