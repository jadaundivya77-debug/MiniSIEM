"""
File Collector for MiniSIEM X
Handles file-based ingestion: JSON, JSONL, CSV, and plain text.
"""
import json
import csv
import io
from typing import List, Dict, Any
from backend.collectors.base_collector import BaseCollector

class FileCollector(BaseCollector):
    def __init__(self):
        super().__init__(name="File Collector", source_type="FILE")

    def collect(self, raw_content: str, filename: str = "") -> List[Dict[str, Any]]:
        """Parses string content from uploaded files into raw dictionary records."""
        events: List[Dict[str, Any]] = []
        clean_content = raw_content.strip()
        if not clean_content:
            return events

        # Try JSON Array
        if clean_content.startswith("[") and clean_content.endswith("]"):
            try:
                parsed = json.loads(clean_content)
                if isinstance(parsed, list):
                    return [item for item in parsed if isinstance(item, dict)]
            except Exception:
                pass

        # Try JSONL (line-by-line JSON)
        is_jsonl = True
        jsonl_events = []
        for line in clean_content.splitlines():
            line_str = line.strip()
            if not line_str:
                continue
            if line_str.startswith("{") and line_str.endswith("}"):
                try:
                    obj = json.loads(line_str)
                    if isinstance(obj, dict):
                        jsonl_events.append(obj)
                    else:
                        is_jsonl = False
                        break
                except Exception:
                    is_jsonl = False
                    break
            else:
                is_jsonl = False
                break

        if is_jsonl and jsonl_events:
            return jsonl_events

        # Try CSV
        if "," in clean_content and "\n" in clean_content:
            try:
                reader = csv.DictReader(io.StringIO(clean_content))
                csv_records = [dict(row) for row in reader if any(row.values())]
                if csv_records:
                    return csv_records
            except Exception:
                pass

        # Fallback to plain text lines
        for line in clean_content.splitlines():
            line_str = line.strip()
            if line_str:
                events.append({
                    "raw_event": line_str,
                    "event_type": "generic_log",
                    "source": "file_import"
                })

        return events

