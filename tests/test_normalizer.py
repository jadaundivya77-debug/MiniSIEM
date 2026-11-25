import pytest
from datetime import datetime, timezone
from backend.processors.normalizer import EventNormalizer
from backend.processors.validator import LogValidator

def test_normalizer_canonical_fields():
    raw = {
        "timestamp": "2026-11-24T12:00:00Z",
        "source": "auth",
        "host": "web01.prod",
        "action": "Failed password for admin",
        "user": "admin",
        "ip": "198.51.100.24",
        "port": 22
    }
    norm = EventNormalizer.normalize(raw)
    assert isinstance(norm["timestamp"], datetime)
    assert norm["timestamp"].tzinfo == timezone.utc
    assert norm["source"] == "linux"
    assert norm["hostname"] == "web01.prod"
    assert norm["event_type"] == "auth_failure"
    assert norm["username"] == "admin"
    assert norm["source_ip"] == "198.51.100.24"
    assert norm["destination_port"] == 22
    assert norm["severity"] == "HIGH"
    assert norm["raw_event"] is not None

def test_validator_valid_and_invalid():
    valid_event = {
        "timestamp": datetime.now(timezone.utc),
        "source": "linux",
        "event_type": "auth_failure",
        "severity": "HIGH",
        "destination_port": 22
    }
    is_valid, errs = LogValidator.validate(valid_event)
    assert is_valid is True
    assert len(errs) == 0

    # Invalid port and severity
    invalid_event = {
        "timestamp": datetime.now(timezone.utc),
        "source": "linux",
        "event_type": "auth_failure",
        "severity": "UNKNOWN_SEV",
        "destination_port": 999999
    }
    is_valid, errs = LogValidator.validate(invalid_event)
    assert is_valid is False
    assert any("port" in e.lower() for e in errs)
    assert any("severity" in e.lower() for e in errs)

