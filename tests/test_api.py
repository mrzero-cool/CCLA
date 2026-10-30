"""Tests for the CLCA REST API (P2.2)."""
from __future__ import annotations

from fastapi.testclient import TestClient

from clca.api.main import app

client = TestClient(app)


def test_healthz():
    response = client.get("/api/v1/healthz")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ok"
    assert data["version"] == "0.4.0"


def test_list_scenarios():
    response = client.get("/api/v1/scenarios")
    assert response.status_code == 200
    data = response.json()
    assert "scenarios" in data
    assert len(data["scenarios"]) >= 5
    # Check scenario structure
    s = data["scenarios"][0]
    assert "scenario_id" in s
    assert "title" in s
    assert "expected_decision" in s


def test_create_run():
    response = client.post("/api/v1/runs", json={"scenario": "safe_code_change"})
    assert response.status_code == 202
    data = response.json()
    assert "run_id" in data
    assert data["scenario_id"] == "safe_code_change"
    assert data["status"] in ("RUNNING", "SUCCEEDED")
    assert "poll_url" in data


def test_create_run_invalid_scenario():
    response = client.post("/api/v1/runs", json={"scenario": "nonexistent_scenario"})
    assert response.status_code == 400


def test_get_run_not_found():
    response = client.get("/api/v1/runs/nonexistent-run-id")
    assert response.status_code == 404


def test_get_run_after_create():
    create_response = client.post("/api/v1/runs", json={"scenario": "safe_code_change"})
    assert create_response.status_code == 202
    run_id = create_response.json()["run_id"]

    get_response = client.get(f"/api/v1/runs/{run_id}")
    assert get_response.status_code == 200
    data = get_response.json()
    assert data["run_id"] == run_id
    assert data["scenario_id"] == "safe_code_change"
    assert data["decision"] in ("PASS", "WARN", "BLOCK", "INCOMPLETE")


def test_list_runs():
    response = client.get("/api/v1/runs")
    assert response.status_code == 200
    data = response.json()
    assert "total" in data
    assert "runs" in data
    assert "limit" in data
    assert "offset" in data


def test_get_run_events():
    create_response = client.post("/api/v1/runs", json={"scenario": "safe_code_change"})
    run_id = create_response.json()["run_id"]

    response = client.get(f"/api/v1/runs/{run_id}/events")
    assert response.status_code == 200
    data = response.json()
    assert data["run_id"] == run_id
    assert "events" in data


def test_integrations():
    response = client.get("/api/v1/integrations")
    assert response.status_code == 200
    data = response.json()
    assert "github" in data


def test_openapi_schema():
    response = client.get("/api/v1/openapi.json")
    assert response.status_code == 200
    data = response.json()
    assert "openapi" in data
    assert "info" in data
    assert data["info"]["title"] == "CLCA Evidence Gate API"
