"""
Log Validator for MiniSIEM X
Validates normalized events, flags malformed records, and enforces structural integrity.
"""
from typing import Dict, Any, List, Tuple
from datetime import datetime

class LogValidator:
    @staticmethod
    def validate(event: Dict[str, Any]) -> Tuple[bool, List[str]]:
        """
        Validates a normalized event.
        Returns: (is_valid: bool, errors: List[str])
        """
        errors = []

        # Check required fields
        if not event.get("event_type"):
            errors.append("Missing required field: event_type")

        if not isinstance(event.get("timestamp"), datetime):
            errors.append("Invalid or missing timestamp object")

        if not event.get("source"):
            errors.append("Missing source identifier")

        # Port validation if provided
        port = event.get("destination_port")
        if port is not None:
            if not isinstance(port, int) or not (1 <= port <= 65535):
                errors.append(f"Destination port out of valid range (1-65535): {port}")

        # Severity validation
        sev = event.get("severity")
        if sev not in ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]:
            errors.append(f"Invalid severity level: {sev}")

        return (len(errors) == 0, errors)

