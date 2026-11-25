import ipaddress
import re
import json
from typing import Any, Optional, Dict

IP_REGEX = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")

def is_valid_ip(ip_str: Optional[str]) -> bool:
    """Validates whether a string is a valid IPv4 or IPv6 address."""
    if not ip_str or not isinstance(ip_str, str):
        return False
    clean_ip = ip_str.strip()
    try:
        ipaddress.ip_address(clean_ip)
        return True
    except ValueError:
        return False

def sanitize_string(value: Optional[str], max_len: int = 500) -> str:
    """Sanitizes text inputs, stripping harmful characters and enforcing length limits."""
    if value is None:
        return ""
    clean = str(value).strip()
    # Remove control characters except newline and tab
    clean = re.sub(r"[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]", "", clean)
    return clean[:max_len]

def safe_json_dumps(data: Any) -> str:
    """Safely serializes data to JSON string handling datetimes and sets."""
    def default_serializer(obj):
        if hasattr(obj, "isoformat"):
            return obj.isoformat()
        if isinstance(obj, (set, frozenset)):
            return list(obj)
        return str(obj)
    return json.dumps(data, default=default_serializer)

def safe_json_loads(data: Optional[str]) -> Dict[str, Any]:
    """Safely loads a JSON string into a dict."""
    if not data:
        return {}
    try:
        parsed = json.loads(data)
        if isinstance(parsed, dict):
            return parsed
        return {"data": parsed}
    except Exception:
        return {"raw": data}

