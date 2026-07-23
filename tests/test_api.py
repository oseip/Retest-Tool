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
# DELETE /api/poll/jobs
# ---------------------------------------------------------------------------

class TestClearPollJobs:
    def test_removes_poll_jobs(self, client):
        for i in range(3):
            ticket = make_ticket(key=f"POLL-{i}")
            scanner._queue_ticket(ticket, "TestClient", source="poll")

        resp = client.delete("/api/poll/jobs")
        assert resp.status_code == 200
        data = resp.json()
        assert data["ok"] is True
        assert data["removed"] == 3

        remaining_poll = [
            j for j in scanner.JOBS.values() if j.get("source", "poll") == "poll"
        ]
        assert remaining_poll == []

    def test_does_not_remove_sweep_or_manual_jobs(self, client):
        ticket_poll   = make_ticket(key="POLL-1")
        ticket_manual = make_ticket(key="MAN-1")
        ticket_sweep  = make_ticket(key="SWEEP-1")

        scanner._queue_ticket(ticket_poll,   "TestClient", source="poll")
        scanner._queue_ticket(ticket_manual, "TestClient", source="manual")
        scanner._queue_ticket(ticket_sweep,  "TestClient", source="sweep")

        resp = client.delete("/api/poll/jobs")
        assert resp.status_code == 200
        assert resp.json()["removed"] == 1

        keys_remaining = {j["ticket_key"] for j in scanner.JOBS.values()}
        assert "POLL-1" not in keys_remaining
        assert "MAN-1" in keys_remaining
        assert "SWEEP-1" in keys_remaining

    def test_does_not_remove_scanning_poll_job(self, client):
        ticket = make_ticket(key="POLL-ACTIVE")
        job_id = scanner._queue_ticket(ticket, "TestClient", source="poll")
        scanner.JOBS[job_id]["status"] = "scanning"

        resp = client.delete("/api/poll/jobs")
        assert resp.status_code == 200
        assert job_id in scanner.JOBS

    def test_empty_queue_returns_zero_removed(self, client):
        resp = client.delete("/api/poll/jobs")
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


class TestReportItemStatusField:
    """The report per-ticket item exposes a Fixed / Not Fixed status column."""

    def test_fixed_status_maps_to_fixed_label(self):
        from src.main import _to_report_item
        item = _to_report_item({"key": "T-1", "summary": "x", "status": "Fixed"})
        assert item["status"] == "Fixed"
        assert item["status_label"] == "Fixed"
        assert item["is_fixed"] is True

    def test_open_status_maps_to_not_fixed(self):
        from src.main import _to_report_item
        item = _to_report_item({"key": "T-2", "summary": "x", "status": "Open"})
        assert item["status_label"] == "Not Fixed"
        assert item["is_fixed"] is False

    def test_remediated_is_not_fixed(self):
        from src.main import _to_report_item
        item = _to_report_item({"key": "T-3", "summary": "x", "status": "Remediated"})
        assert item["status_label"] == "Not Fixed"

    def test_risk_accepted_is_its_own_label(self):
        from src.main import _to_report_item
        item = _to_report_item({"key": "T-5", "summary": "x", "status": "Risk Accepted"})
        assert item["status_label"] == "Risk Accepted"
        assert item["is_fixed"] is False
        assert item["is_risk_accepted"] is True

    def test_missing_status_is_not_fixed(self):
        from src.main import _to_report_item
        item = _to_report_item({"key": "T-4", "summary": "x"})
        assert item["status_label"] == "Not Fixed"
        assert item["status"] == "—"


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


class TestNotFixedKeysApi:
    def test_returns_completed_not_fixed_keys(self, client):
        import src.scanner as scanner
        from tests.conftest import make_ticket

        ticket = make_ticket(key="NF-1", summary="SSL Certificate Expiry on 10.0.0.1")
        job_id = scanner._queue_ticket(ticket, "TestClient")
        with scanner._lock:
            scanner.JOBS[job_id]["status"] = "completed"
            scanner.JOBS[job_id]["verdict"] = "not_fixed"

        resp = client.get("/api/jobs/not-fixed-keys")
        assert resp.status_code == 200
        data = resp.json()
        assert "NF-1" in data["keys"]
        assert data["count"] >= 1

    def test_csv_format(self, client):
        import src.scanner as scanner
        from tests.conftest import make_ticket

        ticket = make_ticket(key="NF-2", summary="SSL Certificate Expiry on 10.0.0.1")
        job_id = scanner._queue_ticket(ticket, "TestClient")
        with scanner._lock:
            scanner.JOBS[job_id]["status"] = "completed"
            scanner.JOBS[job_id]["verdict"] = "not_fixed"

        resp = client.get("/api/jobs/not-fixed-keys?format=csv")
        assert resp.status_code == 200
        assert "NF-2" in resp.text


class TestBulkTransitionCandidates:
    def test_fixed_always_eligible(self):
        from src.main import _bulk_transition_candidates
        import src.scanner as scanner
        from tests.conftest import make_ticket

        job_id = scanner._queue_ticket(make_ticket(key="FX-1"), "TestClient")
        with scanner._lock:
            scanner.JOBS[job_id]["status"] = "completed"
            scanner.JOBS[job_id]["verdict"] = "fixed"
            scanner.JOBS[job_id]["ticket_status"] = "Remediated"

        to_fixed, to_not_fixed = _bulk_transition_candidates()
        assert any(j["ticket_key"] == "FX-1" for j in to_fixed)
        assert not any(j["ticket_key"] == "FX-1" for j in to_not_fixed)

    def test_not_fixed_only_when_at_retest_status(self):
        from src.main import _bulk_transition_candidates, jira
        import src.scanner as scanner
        from tests.conftest import make_ticket

        jira.cfg.retest_status = "Remediated"

        rem_id = scanner._queue_ticket(make_ticket(key="NF-R"), "TestClient")
        open_id = scanner._queue_ticket(make_ticket(key="NF-O"), "TestClient")
        with scanner._lock:
            scanner.JOBS[rem_id]["status"] = "completed"
            scanner.JOBS[rem_id]["verdict"] = "not_fixed"
            scanner.JOBS[rem_id]["ticket_status"] = "Remediated"
            scanner.JOBS[open_id]["status"] = "completed"
            scanner.JOBS[open_id]["verdict"] = "not_fixed"
            scanner.JOBS[open_id]["ticket_status"] = "Open"

        _, to_not_fixed = _bulk_transition_candidates()
        keys = {j["ticket_key"] for j in to_not_fixed}
        assert "NF-R" in keys
        assert "NF-O" not in keys


class TestScanBatch:
    def test_returns_enqueued_ids_and_skips_non_queued(self, client, monkeypatch):
        from tests.conftest import make_ticket

        q1 = scanner._queue_ticket(make_ticket(key="SB-1"), "TestClient")
        q2 = scanner._queue_ticket(make_ticket(key="SB-2"), "TestClient")
        with scanner._lock:
            scanner.JOBS[q2]["status"] = "completed"

        triggered = []
        monkeypatch.setattr(scanner, "trigger_scan", lambda jid, cfg: triggered.append(jid))

        resp = client.post("/api/jobs/scan-batch", json={"job_ids": [q1, q2, "missing"]})
        assert resp.status_code == 200
        data = resp.json()
        assert data["enqueued"] == 1
        assert data["skipped"] == 2
        assert data["enqueued_ids"] == [q1]
        assert triggered == [q1]


class TestBatchScanHelpers:
    def test_csv_filters_unsafe_targets(self):
        from src.main import _parse_assets

        csv_data = b"IP,Port\n10.0.0.1,443\n$(id),80\n"
        assets = _parse_assets(csv_data, "targets.csv")
        assert assets == [{"ip": "10.0.0.1", "port": 443}]

    def test_batch_scan_one_uses_build_scan_command(self, monkeypatch):
        from src.main import _batch_scan_one
        from src.vuln_rules import RULES

        rule = next(r for r in RULES if r.name == "SSL Certificate Expiry")
        captured = {}

        class FakeKali:
            def exec(self, cmd, timeout=60):
                captured["cmd"] = cmd
                captured["timeout"] = timeout
                return ("nmap done\n###XML###\n<xml/>", "", 0)

        _batch_scan_one(FakeKali(), "10.0.0.1", 443, rule, sudo_nmap=True)
        assert captured["cmd"].startswith("sudo nmap ")
        assert "10.0.0.1" in captured["cmd"]
        assert captured["timeout"] == 600

    def test_batch_scan_one_retries_with_pn(self, monkeypatch):
        from src.main import _batch_scan_one
        from src.vuln_rules import RULES

        rule = next(r for r in RULES if r.name == "SSL Certificate Expiry")
        calls = []

        class FakeKali:
            def exec(self, cmd, timeout=60):
                calls.append(cmd)
                if "-Pn" in cmd:
                    return ("host up\n###XML###\n<xml/>", "", 0)
                return ("Host seems down.\n0 hosts up\n###XML###\n<xml/>", "", 0)

        _batch_scan_one(FakeKali(), "10.0.0.1", 443, rule, sudo_nmap=False)
        assert len(calls) == 2
        assert "-Pn" in calls[1]
