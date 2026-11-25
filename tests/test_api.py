import pytest
from fastapi.testclient import TestClient
from backend.main import app
from backend.database import init_db

@pytest.fixture(scope="module")
def client():
    init_db()
    c = TestClient(app)
    return c

def test_health_check(client):
    res = client.get("/health")
    assert res.status_code == 200
    assert res.json()["status"] == "HEALTHY"

def test_auth_login_success_and_failure(client):
    # Success
    res = client.post("/api/auth/login", json={"username": "admin", "password": "Admin@MiniSIEM2026!"})
    assert res.status_code == 200
    token_data = res.json()
    assert "access_token" in token_data
    token = token_data["access_token"]

    # Test /me with token
    me_res = client.get("/api/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert me_res.status_code == 200
    assert me_res.json()["username"] == "admin"

    # Failure
    bad_res = client.post("/api/auth/login", json={"username": "admin", "password": "WrongPassword"})
    assert bad_res.status_code == 401

def test_log_ingest_and_query(client):
    event_payload = {
        "source": "linux",
        "event_type": "auth_failure",
        "username": "test_user",
        "source_ip": "198.51.100.55",
        "severity": "HIGH",
        "raw_event": "sshd: Failed password for test_user from 198.51.100.55"
    }
    ingest_res = client.post("/api/logs/ingest", json=event_payload)
    assert ingest_res.status_code == 200
    data = ingest_res.json()
    assert data["username"] == "test_user"
    assert data["source_ip"] == "198.51.100.55"

    # Query logs
    logs_res = client.get("/api/logs?username=test_user")
    assert logs_res.status_code == 200
    assert len(logs_res.json()) >= 1

def test_dashboard_stats_and_timeline(client):
    stats_res = client.get("/api/dashboard/stats")
    assert stats_res.status_code == 200
    stats = stats_res.json()
    assert "total_events" in stats
    assert "total_alerts" in stats
    assert "detection_engine_status" in stats

    timeline_res = client.get("/api/dashboard/timeline")
    assert timeline_res.status_code == 200
    assert isinstance(timeline_res.json(), list)

def test_reports_export_csv(client):
    res = client.get("/api/reports/export")
    assert res.status_code == 200
    assert "Alert ID" in res.text

def test_simulation_start_and_reset(client):
    sim_res = client.post("/api/simulation/start", json={"scenario": "brute_force"})
    assert sim_res.status_code == 200
    assert sim_res.json()["status"] == "COMPLETED"

    # Verify alerts generated
    alerts_res = client.get("/api/alerts")
    assert alerts_res.status_code == 200
    assert len(alerts_res.json()) >= 1

    # Reset simulation
    reset_res = client.post("/api/simulation/reset")
    assert reset_res.status_code == 200
    assert reset_res.json()["status"] == "SUCCESS"
