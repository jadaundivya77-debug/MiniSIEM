"""
Event Normalizer for MiniSIEM X
Transforms diverse log schemas into the canonical MiniSIEM X Common Event Schema.
"""
import json
from datetime import datetime
from typing import Dict, Any, Optional
from backend.utils.timestamps import parse_to_utc
from backend.utils.helpers import is_valid_ip, sanitize_string, safe_json_dumps

class EventNormalizer:
    @staticmethod
    def normalize(raw_dict: Dict[str, Any], default_source: str = "custom", is_demo: bool = False) -> Dict[str, Any]:
        """
        Normalizes a raw event dictionary into standard schema:
        - timestamp (datetime UTC)
        - source (str)
        - hostname (str or None)
        - event_type (str)
        - username (str or None)
        - source_ip (str or None)
        - destination_ip (str or None)
        - destination_port (int or None)
        - severity (str: INFO, LOW, MEDIUM, HIGH, CRITICAL)
        - raw_event (str)
        - metadata_json (str)
        - is_demo (bool)
        """
        # 1. Normalize Timestamp
        raw_ts = (
            raw_dict.get("timestamp") or 
            raw_dict.get("time") or 
            raw_dict.get("@timestamp") or 
            raw_dict.get("date") or 
            raw_dict.get("datetime")
        )
        norm_timestamp = parse_to_utc(raw_ts)

        # 2. Source Identification
        source = str(raw_dict.get("source") or default_source).lower().strip()
        if source in ["linux", "auth", "sshd", "syslog"]:
            source = "linux"
        elif source in ["windows", "winlog", "security"]:
            source = "windows"
        elif source in ["web", "nginx", "apache", "http", "api"]:
            source = "web"
        elif "simulated" in source or is_demo or raw_dict.get("is_demo"):
            source = "simulated"
            is_demo = True

        # 3. Hostname
        hostname = (
            raw_dict.get("hostname") or 
            raw_dict.get("host") or 
            raw_dict.get("computer") or 
            raw_dict.get("Computer") or 
            raw_dict.get("server")
        )
        if hostname:
            hostname = sanitize_string(str(hostname), max_len=100)

        # 4. Username
        raw_user = (
            raw_dict.get("username") or 
            raw_dict.get("user") or 
            raw_dict.get("TargetUserName") or 
            raw_dict.get("SubjectUserName") or
            raw_dict.get("AccountName") or 
            raw_dict.get("account")
        )
        username = None
        if raw_user and str(raw_user).strip() not in ["-", "N/A", "null", "None", "(unknown)"]:
            username = sanitize_string(str(raw_user), max_len=100)

        # 5. IP Addresses
        raw_src_ip = (
            raw_dict.get("source_ip") or 
            raw_dict.get("src_ip") or 
            raw_dict.get("src") or 
            raw_dict.get("client_ip") or 
            raw_dict.get("ip") or 
            raw_dict.get("IpAddress")
        )
        source_ip = None
        if raw_src_ip and str(raw_src_ip).strip() not in ["-", "N/A", "null", "None", "LOCAL"] and is_valid_ip(str(raw_src_ip)):
            source_ip = str(raw_src_ip).strip()

        raw_dst_ip = (
            raw_dict.get("destination_ip") or 
            raw_dict.get("dest_ip") or 
            raw_dict.get("dst_ip") or 
            raw_dict.get("dst")
        )
        destination_ip = None
        if raw_dst_ip and is_valid_ip(str(raw_dst_ip)):
            destination_ip = str(raw_dst_ip).strip()

        # 6. Destination Port
        raw_port = (
            raw_dict.get("destination_port") or 
            raw_dict.get("dest_port") or 
            raw_dict.get("dst_port") or 
            raw_dict.get("port") or 
            raw_dict.get("IpPort")
        )
        destination_port = None
        if raw_port is not None:
            try:
                port_val = int(raw_port)
                if 1 <= port_val <= 65535:
                    destination_port = port_val
            except Exception:
                pass

        # 7. Event Type Canonicalization (check explicit EventID in payload/metadata too)
        meta_obj = raw_dict.get("metadata") if isinstance(raw_dict.get("metadata"), dict) else {}
        win_event_id = str(raw_dict.get("EventID") or raw_dict.get("event_id") or meta_obj.get("EventID") or "").strip()

        raw_type = str(
            raw_dict.get("event_type") or 
            raw_dict.get("action") or 
            raw_dict.get("type") or 
            raw_dict.get("event") or 
            "generic_event"
        ).lower().strip()

        if win_event_id == "4625" or any(w in raw_type for w in ["fail", "invalid", "denied", "4625"]):
            event_type = "auth_failure"
        elif win_event_id == "4624" or any(w in raw_type for w in ["success", "accept", "logon", "4624"]):
            event_type = "auth_success"
        elif win_event_id == "4672" or any(w in raw_type for w in ["sudo", "elevat", "privilege", "4672", "root"]):
            event_type = "privilege_escalation"
        elif any(w in raw_type for w in ["scan", "probe", "syn"]):
            event_type = "port_scan"
        elif win_event_id == "4720" or any(w in raw_type for w in ["useradd", "account_created", "4720"]):
            event_type = "account_created"
        else:
            event_type = raw_type

        # 8. Severity
        raw_sev = str(raw_dict.get("severity") or "").upper().strip()
        if raw_sev in ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]:
            severity = raw_sev
        else:
            # Infer baseline severity
            if event_type == "auth_failure":
                severity = "HIGH"
            elif event_type == "privilege_escalation":
                severity = "HIGH"
            elif event_type == "port_scan":
                severity = "MEDIUM"
            elif event_type == "auth_success":
                severity = "INFO"
            else:
                severity = "INFO"

        # 9. Raw Event Preservation
        raw_event = str(raw_dict.get("raw_event") or raw_dict)

        # 10. Metadata JSON, EventRecordID & Explicit Origin Classification
        meta = raw_dict.get("metadata") or {}
        if not isinstance(meta, dict):
            meta = {"context": str(meta)}
        # Preserve original extras
        for k, v in raw_dict.items():
            if k not in ["timestamp", "source", "hostname", "event_type", "username", "source_ip", "destination_ip", "destination_port", "severity", "raw_event", "metadata", "is_demo", "origin_type"]:
                meta[k] = v

        raw_rec_id = meta.get("EventRecordID") or raw_dict.get("event_record_id")
        event_record_id = None
        if raw_rec_id is not None and str(raw_rec_id).isdigit():
            event_record_id = int(raw_rec_id)

        final_is_demo = bool(is_demo or raw_dict.get("is_demo", False))
        explicit_origin = raw_dict.get("origin_type")
        if final_is_demo or source == "simulated":
            origin_type = "SIMULATED"
            final_is_demo = True
        elif explicit_origin:
            origin_type = sanitize_string(str(explicit_origin), max_len=40).upper()
        elif source == "windows" and (meta.get("collector") == "windows_event_log" or event_record_id is not None):
            origin_type = "REAL_WINDOWS"
        else:
            origin_type = "INGESTED_API"

        return {
            "timestamp": norm_timestamp,
            "source": source,
            "hostname": hostname,
            "event_type": event_type,
            "username": username,
            "source_ip": source_ip,
            "destination_ip": destination_ip,
            "destination_port": destination_port,
            "severity": severity,
            "raw_event": raw_event,
            "metadata_json": safe_json_dumps(meta),
            "event_record_id": event_record_id,
            "origin_type": origin_type,
            "is_demo": final_is_demo,
        }

