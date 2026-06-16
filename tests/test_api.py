"""
Tests for HTTP endpoints in src/main.py

Uses FastAPI TestClient with scanner state manipulated directly.
All external dependencies (Jira, SSH) are mocked via session-wide patches
in conftest.py that were applied before src.main was first imported.
"""

import pytest
from fastapi.testclient import TestClient

from src.main import app
import src.scanner as scanner
from tests.conftest import make_ticket


@pytest.fixture(scope="module")
def client():
    with TestClient(app) as c:
        yield c


# ---------------------------------------------------------------------------
# GET /api/clients
# ---------------------------------------------------------------------------

class TestListClients:
    def test_returns_client_list(self, client):
        resp = client.get("/api/clients")
        assert resp.status_code == 200
        data = resp.json()
        assert isinstance(data, list)
        assert len(data) >= 1
        assert data[0]["label"] == "TestClient"

    def test_client_has_label_and_name(self, client):
        resp = client.get("/api/clients")
        for c in resp.json():
            assert "label" in c
            assert "name" in c


# ---------------------------------------------------------------------------
# GET /api/jobs
# ---------------------------------------------------------------------------

class TestListJobs:
    def test_empty_when_no_jobs(self, client):
        resp = client.get("/api/jobs")
        assert resp.status_code == 200
        assert resp.json() == []

    def test_returns_queued_job(self, client):
        ticket = make_ticket(key="TEST-10")
        job_id = scanner._queue_ticket(ticket, "TestClient")

        resp = client.get("/api/jobs")
        assert resp.status_code == 200
        keys = [j["ticket_key"] for j in resp.json()]
        assert "TEST-10" in keys


# ---------------------------------------------------------------------------
# GET /api/jobs/{job_id}
# ---------------------------------------------------------------------------

class TestGetJob:
    def test_returns_job_by_id(self, client):
        ticket = make_ticket(key="TEST-20")
        job_id = scanner._queue_ticket(ticket, "TestClient")

        resp = client.get(f"/api/jobs/{job_id}")
        assert resp.status_code == 200
        assert resp.json()["ticket_key"] == "TEST-20"

    def test_404_for_unknown_id(self, client):
        resp = client.get("/api/jobs/nonexistent-id")
        assert resp.status_code == 404


# ---------------------------------------------------------------------------
# DELETE /api/jobs/{job_id}
# ---------------------------------------------------------------------------

class TestRemoveJob:
    def test_removes_job_and_clears_seen_key(self, client):
        ticket = make_ticket(key="TEST-30")
        job_id = scanner._queue_ticket(ticket, "TestClient")
        scanner.SEEN_KEYS.add("TEST-30")

        resp = client.delete(f"/api/jobs/{job_id}")
        assert resp.status_code == 200
        assert resp.json()["ok"] is True
        assert job_id not in scanner.JOBS
        assert "TEST-30" not in scanner.SEEN_KEYS

    def test_404_for_unknown_job(self, client):
        resp = client.delete("/api/jobs/no-such-job")
        assert resp.status_code == 404


# ---------------------------------------------------------------------------
# POST /api/jobs/{job_id}/reset
# ---------------------------------------------------------------------------

class TestResetJob:
    def test_resets_completed_job_to_queued(self, client):
        ticket = make_ticket(key="TEST-40")
        job_id = scanner._queue_ticket(ticket, "TestClient")
        scanner.JOBS[job_id].update({
            "status": "completed",
            "verdict": "fixed",
            "verdict_reason": "done",
            "output_lines": ["some output"],
            "error": None,
            "completed_at": "2024-01-01T00:00:00",
        })

        resp = client.post(f"/api/jobs/{job_id}/reset")
        assert resp.status_code == 200
        job = scanner.JOBS[job_id]
        assert job["status"] == "queued"
        assert job["verdict"] is None
        assert job["verdict_reason"] is None
        assert job["output_lines"] == []
        assert job["completed_at"] is None

    def test_404_for_unknown_job(self, client):
        resp = client.post("/api/jobs/no-such-job/reset")
        assert resp.status_code == 404


# ---------------------------------------------------------------------------
# POST /api/jobs/{job_id}/stop
# ---------------------------------------------------------------------------

class TestStopJob:
    def test_404_for_unknown_job(self, client):
        resp = client.post("/api/jobs/no-such-job/stop")
        assert resp.status_code == 404

    def test_400_when_job_not_scanning(self, client):
        ticket = make_ticket(key="TEST-50")
        job_id = scanner._queue_ticket(ticket, "TestClient")
        # Status is 'queued', not 'scanning'
        resp = client.post(f"/api/jobs/{job_id}/stop")
        assert resp.status_code == 400

    def test_stop_signals_running_scan(self, client):
        import threading
        ticket = make_ticket(key="TEST-55")
        job_id = scanner._queue_ticket(ticket, "TestClient")
        scanner.JOBS[job_id]["status"] = "scanning"
        event = threading.Event()
        scanner._stop_events[job_id] = event

        resp = client.post(f"/api/jobs/{job_id}/stop")
        assert resp.status_code == 200
        assert event.is_set()


# ---------------------------------------------------------------------------
# POST /api/jobs/{job_id}/scan
# ---------------------------------------------------------------------------

class TestStartScan:
    def test_404_for_unknown_job(self, client):
        resp = client.post("/api/jobs/no-such-job/scan")
        assert resp.status_code == 404

    def test_400_when_job_not_queued(self, client):
        ticket = make_ticket(key="TEST-60")
        job_id = scanner._queue_ticket(ticket, "TestClient")
        scanner.JOBS[job_id]["status"] = "completed"

        resp = client.post(f"/api/jobs/{job_id}/scan")
        assert resp.status_code == 400

    def test_queued_job_is_accepted(self, client):
        ticket = make_ticket(key="TEST-61")
        job_id = scanner._queue_ticket(ticket, "TestClient")
        # trigger_scan tries to start a worker thread; that's OK in tests
        resp = client.post(f"/api/jobs/{job_id}/scan")
        assert resp.status_code == 200
        assert resp.json()["ok"] is True


# ---------------------------------------------------------------------------
# DELETE /api/sweep/jobs
# ---------------------------------------------------------------------------

class TestClearSweepJobs:
    def test_removes_sweep_jobs(self, client):
        for i in range(3):
            ticket = make_ticket(key=f"SWEEP-{i}")
            scanner._queue_ticket(ticket, "TestClient", source="sweep")

        resp = client.delete("/api/sweep/jobs")
        assert resp.status_code == 200
        data = resp.json()
        assert data["ok"] is True
        assert data["removed"] == 3

        remaining_sweep = [
            j for j in scanner.JOBS.values() if j.get("source") == "sweep"
        ]
        assert remaining_sweep == []

    def test_does_not_remove_poll_or_manual_jobs(self, client):
        ticket_poll   = make_ticket(key="POLL-1")
        ticket_manual = make_ticket(key="MAN-1")
        ticket_sweep  = make_ticket(key="SWEEP-99")

        scanner._queue_ticket(ticket_poll,   "TestClient", source="poll")
        scanner._queue_ticket(ticket_manual, "TestClient", source="manual")
        scanner._queue_ticket(ticket_sweep,  "TestClient", source="sweep")

        resp = client.delete("/api/sweep/jobs")
        assert resp.status_code == 200
        assert resp.json()["removed"] == 1

        keys_remaining = {j["ticket_key"] for j in scanner.JOBS.values()}
        assert "POLL-1" in keys_remaining
        assert "MAN-1" in keys_remaining
        assert "SWEEP-99" not in keys_remaining

    def test_does_not_remove_scanning_sweep_job(self, client):
        ticket = make_ticket(key="SWEEP-ACTIVE")
        job_id = scanner._queue_ticket(ticket, "TestClient", source="sweep")
        scanner.JOBS[job_id]["status"] = "scanning"

        resp = client.delete("/api/sweep/jobs")
        assert resp.status_code == 200
        assert job_id in scanner.JOBS

    def test_empty_queue_returns_zero_removed(self, client):
        resp = client.delete("/api/sweep/jobs")
        assert resp.status_code == 200
        assert resp.json()["removed"] == 0


# ---------------------------------------------------------------------------
# GET /api/logs
# ---------------------------------------------------------------------------

class TestGetLogs:
    def test_returns_list(self, client):
        resp = client.get("/api/logs")
        assert resp.status_code == 200
        assert isinstance(resp.json(), list)

    def test_log_entries_are_strings(self, client):
        scanner._app_log("api test log entry")
        resp = client.get("/api/logs")
        logs = resp.json()
        assert any("api test log entry" in entry for entry in logs)


# ---------------------------------------------------------------------------
# GET /api/ssh/status
# ---------------------------------------------------------------------------

class TestSshStatus:
    def test_returns_dict(self, client):
        resp = client.get("/api/ssh/status")
        assert resp.status_code == 200
        assert isinstance(resp.json(), dict)

    def test_client_label_present(self, client):
        resp = client.get("/api/ssh/status")
        data = resp.json()
        assert "TestClient" in data


# ---------------------------------------------------------------------------
# GET /api/report — validation only (no real Jira calls)
# ---------------------------------------------------------------------------

class TestReportValidation:
    def test_bad_month_format_returns_400(self, client):
        resp = client.get("/api/report?client=TestClient&month=not-a-date")
        assert resp.status_code == 400

    def test_current_month_returns_400(self, client):
        from datetime import date
        today = date.today()
        month = today.strftime("%Y-%m")
        resp = client.get(f"/api/report?client=TestClient&month={month}")
        assert resp.status_code == 400

    def test_future_month_returns_400(self, client):
        resp = client.get("/api/report?client=TestClient&month=2099-01")
        assert resp.status_code == 400


# ---------------------------------------------------------------------------
# /api/tunnels — validation only (no real SSH connections)
# ---------------------------------------------------------------------------

class TestTunnelsApi:
    def test_get_tunnels_returns_list(self, client):
        resp = client.get("/api/tunnels")
        assert resp.status_code == 200
        assert isinstance(resp.json(), list)

    def test_unknown_client_returns_404(self, client):
        resp = client.post("/api/tunnels", json={
            "label": "NoSuchClient",
            "target_host": "127.0.0.1",
            "target_port": 8080,
            "local_port": 59123,
        })
        assert resp.status_code == 404

    def test_bad_target_port_returns_400(self, client):
        resp = client.post("/api/tunnels", json={
            "label": "TestClient",
            "target_host": "127.0.0.1",
            "target_port": 0,
            "local_port": 59124,
        })
        assert resp.status_code == 400

    def test_bad_local_port_returns_400(self, client):
        resp = client.post("/api/tunnels", json={
            "label": "TestClient",
            "target_host": "127.0.0.1",
            "target_port": 8080,
            "local_port": 70000,
        })
        assert resp.status_code == 400

    def test_delete_unknown_tunnel_returns_404(self, client):
        resp = client.delete("/api/tunnels/no-such-tunnel")
        assert resp.status_code == 404
