from datetime import datetime, timezone
from typing import Optional
from dateutil import parser as date_parser

def parse_to_utc(timestamp_input: Optional[str | int | float | datetime]) -> datetime:
    """
    Parses various timestamp inputs (ISO string, epoch int/float, syslog date, datetime)
    and returns a standardized UTC datetime object.
    """
    if timestamp_input is None:
        return datetime.now(timezone.utc)
    
    if isinstance(timestamp_input, datetime):
        if timestamp_input.tzinfo is None:
            return timestamp_input.replace(tzinfo=timezone.utc)
        return timestamp_input.astimezone(timezone.utc)
    
    # Numeric epoch timestamps
    if isinstance(timestamp_input, (int, float)):
        # Handle milliseconds vs seconds
        if timestamp_input > 1e11:
            timestamp_input = timestamp_input / 1000.0
        return datetime.fromtimestamp(timestamp_input, tz=timezone.utc)
    
    # String timestamps
    ts_str = str(timestamp_input).strip()
    if not ts_str:
        return datetime.now(timezone.utc)
        
    try:
        # Check if numeric string
        if ts_str.replace(".", "", 1).isdigit():
            epoch = float(ts_str)
            if epoch > 1e11:
                epoch = epoch / 1000.0
            return datetime.fromtimestamp(epoch, tz=timezone.utc)

        parsed = date_parser.parse(ts_str)
        if parsed.tzinfo is None:
            # Assume UTC if not specified
            parsed = parsed.replace(tzinfo=timezone.utc)
        else:
            parsed = parsed.astimezone(timezone.utc)
        return parsed
    except Exception:
        # Fallback to current UTC time if unparseable
        return datetime.now(timezone.utc)

def format_iso_utc(dt: Optional[datetime]) -> str:
    """Formats datetime to standard ISO 8601 UTC string."""
    if dt is None:
        return ""
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).isoformat()

