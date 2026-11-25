import pytest
from backend.processors.parser import LogParser

def test_parse_json_array():
    raw = '[{"event": "login", "user": "alice"}, {"event": "logout", "user": "alice"}]'
    events = LogParser.parse(raw)
    assert len(events) == 2
    assert events[0]["user"] == "alice"
    assert events[1]["event"] == "logout"

def test_parse_jsonl():
    raw = '{"event": "login", "ip": "1.2.3.4"}\n{"event": "sudo", "user": "root"}'
    events = LogParser.parse(raw)
    assert len(events) == 2
    assert events[0]["ip"] == "1.2.3.4"
    assert events[1]["user"] == "root"

def test_parse_csv():
    raw = "timestamp,source_ip,username,event_type\n2026-11-24T10:00:00Z,192.168.1.1,admin,auth_failure\n2026-11-24T10:00:05Z,192.168.1.1,admin,auth_success"
    events = LogParser.parse(raw)
    assert len(events) == 2
    assert events[0]["username"] == "admin"
    assert events[0]["event_type"] == "auth_failure"
    assert events[1]["event_type"] == "auth_success"

def test_parse_empty():
    assert LogParser.parse("") == []
    assert LogParser.parse("   ") == []

