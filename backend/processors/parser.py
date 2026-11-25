"""
Log Parser for MiniSIEM X
Auto-detects format (JSON, JSONL, CSV, Syslog/Key-Value) and extracts event dicts.
"""
import json
import csv
import io
import re
from typing import List, Dict, Any, Union

class LogParser:
    @staticmethod
    def parse(raw_content: Union[str, bytes, List[Any], Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Parses any incoming raw log data into a uniform list of raw dictionaries."""
        if isinstance(raw_content, bytes):
            try:
                raw_content = raw_content.decode("utf-8")
            except UnicodeDecodeError:
                raw_content = raw_content.decode("latin-1", errors="replace")

        if isinstance(raw_content, dict):
            return [raw_content]

        if isinstance(raw_content, list):
            results = []
            for item in raw_content:
                if isinstance(item, dict):
                    results.append(item)
                elif isinstance(item, str):
                    results.extend(LogParser._parse_string(item))
            return results

        if isinstance(raw_content, str):
            return LogParser._parse_string(raw_content)

        return []

    @staticmethod
    def _parse_string(text: str) -> List[Dict[str, Any]]:
        clean_text = text.strip()
        if not clean_text:
            return []

        # 1. JSON Array
        if clean_text.startswith("[") and clean_text.endswith("]"):
            try:
                data = json.loads(clean_text)
                if isinstance(data, list):
                    return [item for item in data if isinstance(item, dict)]
            except Exception:
                pass

        # 2. JSON Single Object
        if clean_text.startswith("{") and clean_text.endswith("}") and "\n" not in clean_text:
            try:
                data = json.loads(clean_text)
                if isinstance(data, dict):
                    return [data]
            except Exception:
                pass

        # 3. JSONL (Newline-delimited JSON)
        lines = clean_text.splitlines()
        jsonl_matches = []
        is_pure_jsonl = True
        for line in lines:
            line_str = line.strip()
            if not line_str:
                continue
            if line_str.startswith("{") and line_str.endswith("}"):
                try:
                    obj = json.loads(line_str)
                    if isinstance(obj, dict):
                        jsonl_matches.append(obj)
                    else:
                        is_pure_jsonl = False
                        break
                except Exception:
                    is_pure_jsonl = False
                    break
            else:
                is_pure_jsonl = False
                break

        if is_pure_jsonl and jsonl_matches:
            return jsonl_matches

        # 4. CSV Check (requires header with common log fields)
        if "," in lines[0] and len(lines) > 1:
            try:
                reader = csv.DictReader(io.StringIO(clean_text))
                headers = [h.lower() for h in (reader.fieldnames or [])]
                if any(k in headers for k in ["ip", "source_ip", "event", "event_type", "user", "username", "timestamp", "status"]):
                    rows = [dict(r) for r in reader if any(r.values())]
                    if rows:
                        return rows
            except Exception:
                pass

        # 5. Key-Value format (e.g., event=login user=admin src_ip=1.2.3.4)
        kv_events = []
        for line in lines:
            line_str = line.strip()
            if not line_str:
                continue
            kv_pairs = re.findall(r'(\w+)=(?:"([^"]*)"|(\S+))', line_str)
            if len(kv_pairs) >= 2:
                event_dict = {}
                for k, v1, v2 in kv_pairs:
                    event_dict[k] = v1 if v1 else v2
                event_dict["raw_event"] = line_str
                kv_events.append(event_dict)
            else:
                kv_events.append({"raw_event": line_str, "event_type": "generic_log"})

        return kv_events

