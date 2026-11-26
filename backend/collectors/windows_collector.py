"""
Windows Event Log Collector & Parser for MiniSIEM X
Parses Windows Security Events:
- Event ID 4624: Successful logon
- Event ID 4625: Failed logon
- Event ID 4672: Special privileges assigned
- Event ID 4720: User account created
Supports JSON/dict payloads, text blocks, and native Windows Event XML (wevtutil).
"""
import re
import socket
import xml.etree.ElementTree as ET
from typing import List, Dict, Any, Optional
from backend.collectors.base_collector import BaseCollector

NOISY_SYSTEM_ACCOUNTS = {
    "system",
    "local service",
    "network service",
    "anonymous logon",
}

EVENT_ID_MAP = {
    "4624": ("auth_success", "INFO", "Successful Windows logon"),
    "4625": ("auth_failure", "HIGH", "Failed Windows logon attempt"),
    "4672": ("privilege_escalation", "HIGH", "Special privileges assigned to new logon"),
    "4720": ("account_created", "MEDIUM", "New Windows user account created"),
}

LOGON_TYPE_NAMES = {
    "2": "Interactive (Local Console)",
    "3": "Network (SMB/Share)",
    "4": "Batch (Scheduled Task)",
    "5": "Service",
    "7": "Unlock",
    "8": "NetworkCleartext",
    "9": "NewCredentials (RunAs)",
    "10": "RemoteInteractive (RDP)",
    "11": "CachedInteractive",
}


def clean_windows_field(value: Optional[str]) -> Optional[str]:
    """Converts placeholder Windows event values ('-', 'N/A', empty) into None."""
    if value is None:
        return None
    cleaned = str(value).strip()
    if not cleaned or cleaned in {"-", "N/A", "null", "None", "LOCAL", "(unknown)"}:
        return None
    return cleaned


def is_noisy_system_account(username: Optional[str]) -> bool:
    """Returns True for built-in Windows OS service/machine accounts that create background noise."""
    if not username:
        return False
    lower = username.strip().lower()
    if lower in NOISY_SYSTEM_ACCOUNTS:
        return True
    if lower.startswith("dwm-") or lower.startswith("umfd-"):
        return True
    if lower.endswith("$"):
        return True
    return False


class WindowsCollector(BaseCollector):
    def __init__(self):
        super().__init__(name="Windows Collector", source_type="WINDOWS")

    def collect(self, raw_input: Any, include_system: bool = True) -> List[Dict[str, Any]]:
        """Parses Windows event logs provided as XML string, dicts, JSON list, or text blocks."""
        events: List[Dict[str, Any]] = []
        if isinstance(raw_input, list):
            for item in raw_input:
                if isinstance(item, dict):
                    events.append(self._parse_dict(item))
                elif isinstance(item, str):
                    events.extend(self._parse_string(item, include_system=include_system))
        elif isinstance(raw_input, dict):
            events.append(self._parse_dict(raw_input))
        elif isinstance(raw_input, str):
            events.extend(self._parse_string(raw_input, include_system=include_system))

        return [e for e in events if e]

    def _parse_string(self, text: str, include_system: bool = True) -> List[Dict[str, Any]]:
        stripped = text.strip()
        if not stripped:
            return []
        if stripped.startswith("<"):
            return self.parse_windows_xml(stripped, include_system=include_system)
        events = []
        for block in stripped.split("\n\n"):
            if block.strip():
                parsed = self._parse_text(block.strip())
                if parsed:
                    events.append(parsed)
        return events

    def parse_windows_xml(self, xml_text: str, include_system: bool = False) -> List[Dict[str, Any]]:
        """
        Parses XML output from `wevtutil qe Security /f:xml /e:Events`.
        Handles missing usernames, missing IP addresses, and EventRecordID extraction.
        """
        cleaned_xml = xml_text.strip()
        if not cleaned_xml:
            return []

        # Strip XML namespace so tag lookups work cleanly across Windows versions
        cleaned_xml = re.sub(r"\sxmlns=['\"][^'\"]+['\"]", "", cleaned_xml)

        try:
            root = ET.fromstring(cleaned_xml)
        except ET.ParseError:
            # Wrap multiple <Event> elements if not enclosed in a root node
            root = ET.fromstring(f"<Events>{cleaned_xml}</Events>")

        event_nodes = [root] if root.tag == "Event" else root.findall(".//Event")
        parsed_events: List[Dict[str, Any]] = []
        default_host = socket.gethostname()

        for node in event_nodes:
            system = node.find("System")
            if system is None:
                continue

            event_id = (system.findtext("EventID") or "").strip()
            if event_id not in EVENT_ID_MAP:
                continue

            record_id_text = (system.findtext("EventRecordID") or "").strip()
            record_id = int(record_id_text) if record_id_text.isdigit() else None

            time_created = system.find("TimeCreated")
            timestamp = time_created.attrib.get("SystemTime") if time_created is not None else None
            computer = clean_windows_field(system.findtext("Computer")) or default_host

            data_fields: Dict[str, str] = {}
            for data_el in node.findall(".//EventData/Data"):
                key = data_el.attrib.get("Name")
                if key:
                    data_fields[key] = (data_el.text or "").strip()

            # 4624/4625 use TargetUserName; 4672 uses SubjectUserName
            username = clean_windows_field(
                data_fields.get("TargetUserName") or data_fields.get("SubjectUserName")
            )
            domain = clean_windows_field(
                data_fields.get("TargetDomainName") or data_fields.get("SubjectDomainName")
            )

            if not include_system and is_noisy_system_account(username):
                continue

            logon_type = clean_windows_field(data_fields.get("LogonType"))
            if not include_system and event_id == "4624" and logon_type in {"0", "5"} and not clean_windows_field(data_fields.get("IpAddress")):
                # Skip internal OS service logons without remote IP to prevent noisy alerts/logs
                continue

            source_ip = clean_windows_field(data_fields.get("IpAddress"))
            dest_port_raw = clean_windows_field(data_fields.get("IpPort"))
            dest_port = int(dest_port_raw) if dest_port_raw and dest_port_raw.isdigit() and 1 <= int(dest_port_raw) <= 65535 else None
            workstation = clean_windows_field(data_fields.get("WorkstationName"))
            privileges = clean_windows_field(data_fields.get("PrivilegeList"))
            failure_reason = clean_windows_field(data_fields.get("FailureReason"))
            status_code = clean_windows_field(data_fields.get("Status"))
            sub_status = clean_windows_field(data_fields.get("SubStatus"))

            event_type, severity, summary_label = EVENT_ID_MAP[event_id]
            logon_desc = LOGON_TYPE_NAMES.get(logon_type or "", f"Type {logon_type}" if logon_type else "Unknown")

            raw_parts = [
                f"Windows Security Event {event_id}: {summary_label}.",
                f"Computer={computer}",
                f"RecordID={record_id}" if record_id is not None else None,
                f"User={f'{domain}\\{username}' if domain and username else (username or 'Unknown')}",
                f"LogonType={logon_desc}" if logon_type else None,
                f"SourceIP={source_ip or 'Local/Unspecified'}",
                f"Workstation={workstation}" if workstation else None,
                f"Privileges={privileges}" if privileges else None,
                f"Status={status_code}/{sub_status}" if status_code else None,
                f"FailureReason={failure_reason}" if failure_reason else None,
            ]
            raw_summary = " | ".join(p for p in raw_parts if p)

            metadata: Dict[str, Any] = {
                "EventID": event_id,
                "EventRecordID": record_id,
                "LogonType": logon_type,
                "LogonTypeName": logon_desc if logon_type else None,
                "TargetDomainName": domain,
                "WorkstationName": workstation,
                "PrivilegeList": privileges,
                "Status": status_code,
                "SubStatus": sub_status,
                "FailureReason": failure_reason,
                "collector": "windows_event_log",
            }
            # Drop None values from metadata to keep payloads compact
            metadata = {k: v for k, v in metadata.items() if v is not None}

            parsed_events.append({
                "timestamp": timestamp,
                "source": "windows",
                "hostname": computer,
                "event_type": event_type,
                "username": username,
                "source_ip": source_ip,
                "destination_port": dest_port,
                "severity": severity,
                "raw_event": raw_summary,
                "metadata": metadata,
                "is_demo": False,
            })

        return parsed_events

    def _parse_dict(self, data: Dict[str, Any]) -> Dict[str, Any]:
        event_id = str(data.get("EventID") or data.get("event_id") or "")
        username = clean_windows_field(
            data.get("TargetUserName") or data.get("SubjectUserName") or data.get("username") or data.get("AccountName")
        )
        source_ip = clean_windows_field(data.get("IpAddress") or data.get("source_ip"))
        dest_port = data.get("IpPort") or data.get("destination_port")
        hostname = clean_windows_field(data.get("Computer") or data.get("hostname"))

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
            "timestamp": data.get("timestamp"),
            "source": "windows",
            "hostname": hostname,
            "event_type": event_type,
            "username": username,
            "source_ip": source_ip,
            "destination_port": int(dest_port) if dest_port and str(dest_port).isdigit() and 1 <= int(dest_port) <= 65535 else None,
            "severity": severity,
            "raw_event": str(data.get("raw_event") or data),
            "metadata": {"EventID": event_id, **data},
            "is_demo": bool(data.get("is_demo", False)),
        }

    def _parse_text(self, text: str) -> Dict[str, Any]:
        event_id_match = re.search(r"Event ID:\s*(\d+)", text, re.IGNORECASE)
        user_match = re.search(r"Account Name:\s*(\S+)", text, re.IGNORECASE)
        ip_match = re.search(r"Source Network Address:\s*(\S+)", text, re.IGNORECASE)

        event_id = event_id_match.group(1) if event_id_match else "4624"
        username = clean_windows_field(user_match.group(1) if user_match else None)
        source_ip = clean_windows_field(ip_match.group(1) if ip_match else None)

        event_type, severity, _ = EVENT_ID_MAP.get(event_id, ("windows_security_event", "INFO", ""))

        return {
            "source": "windows",
            "event_type": event_type,
            "username": username,
            "source_ip": source_ip,
            "severity": severity,
            "raw_event": text,
            "metadata": {"EventID": event_id},
            "is_demo": False,
        }
