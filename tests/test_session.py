"""
Tests for two-session architecture in src/main.py

Covers:
- GET  /api/session   — returns active session and non_axian_configured flag
- POST /api/session   — validates input, blocks switch when not configured
- GET  /api/clients   — returns Axian vs Non-Axian clients based on session
- GET  /api/jobs      — filters jobs by their tagged session
- GET  /api/ssh/status — filters clients by active session
- _get_client()       — finds client across both sessions
- _jira_for_label()   — routes to correct Jira client
- _jira_for_job()     — routes by job's session field
- scanner._queue_ticket session tagging
- run_poll_cycle session tagging on jobs
"""

import pytest
from unittest.mock import MagicMock, patch
from fastapi.testclient import TestClient

import src.main as main_mod
import src.scanner as scanner
import src.connections as connections
from src.config import JiraSecondaryConfig, ClientConfig
from tests.conftest import make_ticket


@pytest.fixture(scope="module")
def client():
    with TestClient(main_mod.app) as c:
        yield c


@pytest.fixture(autouse=True)
def reset_session():
    """Restore active_session to 'axian' and clean secondary config after each test."""
    original_session = main_mod.active_session
    original_jira_secondary = main_mod.jira_secondary
    original_clients_secondary = main_mod.cfg.clients_secondary[:]
    original_jira_secondary_cfg = main_mod.cfg.jira_secondary

    yield

    main_mod.active_session = original_session
    main_mod.jira_secondary = original_jira_secondary
    main_mod.cfg.clients_secondary = original_clients_secondary
    main_mod.cfg.jira_secondary = original_jira_secondary_cfg
    # Remove any CPEL entry seeded into connections during test
    connections._status.pop("CPEL", None)


def _add_secondary(url="https://tickets.test.com", token="test-pat"):
    """Configure Non-Axian on the live cfg for testing, including seeding SSH status."""
    main_mod.cfg.jira_secondary = JiraSecondaryConfig(url=url, api_token=token)
    main_mod.cfg.clients_secondary = [
        ClientConfig(
            label="CPEL", name="CPEL Client",
            kali_port=22, kali_user="kali", kali_password="kalipass",
        )
    ]
    main_mod.jira_secondary = MagicMock()
    # Seed connections status so the SSH status endpoint can return it
    connections._status.setdefault("CPEL", "disconnected")


# ---------------------------------------------------------------------------
# GET /api/session
# ---------------------------------------------------------------------------

class TestGetSession:
    def test_default_session_is_axian(self, client):
        resp = client.get("/api/session")
        assert resp.status_code == 200
        assert resp.json()["active"] == "axian"

    def test_non_axian_not_configured_by_default(self, client):
        resp = client.get("/api/session")
        assert resp.json()["non_axian_configured"] is False

    def test_non_axian_configured_true_when_secondary_set(self, client):
        _add_secondary()
        resp = client.get("/api/session")
        assert resp.json()["non_axian_configured"] is True

    def test_reflects_session_after_switch(self, client):
        _add_secondary()
        client.post("/api/session", json={"session": "non_axian"})
        resp = client.get("/api/session")
        assert resp.json()["active"] == "non_axian"


# ---------------------------------------------------------------------------
# POST /api/session
# ---------------------------------------------------------------------------

class TestSetSession:
    def test_switch_to_axian_always_succeeds(self, client):
        resp = client.post("/api/session", json={"session": "axian"})
        assert resp.status_code == 200
        assert resp.json()["ok"] is True
        assert resp.json()["active"] == "axian"

    def test_invalid_session_name_returns_400(self, client):
        resp = client.post("/api/session", json={"session": "invalid"})
        assert resp.status_code == 400

    def test_switch_to_non_axian_without_config_returns_400(self, client):
        # Secondary not configured → expect 400
        resp = client.post("/api/session", json={"session": "non_axian"})
        assert resp.status_code == 400

    def test_switch_to_non_axian_with_config_succeeds(self, client):
        _add_secondary()
        resp = client.post("/api/session", json={"session": "non_axian"})
        assert resp.status_code == 200
        assert resp.json()["active"] == "non_axian"

    def test_switch_to_non_axian_without_clients_returns_400(self, client):
        # Configure Jira but no clients
        main_mod.cfg.jira_secondary = JiraSecondaryConfig(
            url="https://tickets.test.com", api_token="tok"
        )
        main_mod.cfg.clients_secondary = []
        main_mod.jira_secondary = MagicMock()

        resp = client.post("/api/session", json={"session": "non_axian"})
        assert resp.status_code == 400


# ---------------------------------------------------------------------------
# GET /api/clients — session filtering
# ---------------------------------------------------------------------------

class TestSessionClients:
    def test_axian_session_returns_primary_clients(self, client):
        main_mod.active_session = "axian"
        resp = client.get("/api/clients")
        assert resp.status_code == 200
        labels = [c["label"] for c in resp.json()]
        assert "TestClient" in labels

    def test_non_axian_session_returns_secondary_clients(self, client):
        _add_secondary()
        main_mod.active_session = "non_axian"
        resp = client.get("/api/clients")
        assert resp.status_code == 200
        labels = [c["label"] for c in resp.json()]
        assert "CPEL" in labels
        assert "TestClient" not in labels

    def test_non_axian_session_empty_when_no_secondary_clients(self, client):
        main_mod.cfg.jira_secondary = JiraSecondaryConfig(
            url="https://tickets.test.com", api_token="tok"
        )
        main_mod.cfg.clients_secondary = []
        main_mod.active_session = "non_axian"
        resp = client.get("/api/clients")
        assert resp.status_code == 200
        assert resp.json() == []


# ---------------------------------------------------------------------------
# GET /api/jobs — session filtering
# ---------------------------------------------------------------------------

class TestSessionJobs:
    def test_axian_jobs_visible_in_axian_session(self, client):
        main_mod.active_session = "axian"
        ticket = make_ticket(key="AXG-1")
        scanner._queue_ticket(ticket, "TestClient", session="axian")

        resp = client.get("/api/jobs")
        keys = [j["ticket_key"] for j in resp.json()]
        assert "AXG-1" in keys

    def test_non_axian_jobs_not_visible_in_axian_session(self, client):
        main_mod.active_session = "axian"
        ticket = make_ticket(key="CPEL-5")
        scanner._queue_ticket(ticket, "CPEL", session="non_axian")

        resp = client.get("/api/jobs")
        keys = [j["ticket_key"] for j in resp.json()]
        assert "CPEL-5" not in keys

    def test_non_axian_jobs_visible_in_non_axian_session(self, client):
        _add_secondary()
        main_mod.active_session = "non_axian"
        ticket = make_ticket(key="CPEL-10")
        scanner._queue_ticket(ticket, "CPEL", session="non_axian")

        resp = client.get("/api/jobs")
        keys = [j["ticket_key"] for j in resp.json()]
        assert "CPEL-10" in keys

    def test_axian_jobs_not_visible_in_non_axian_session(self, client):
        _add_secondary()
        main_mod.active_session = "non_axian"
        ticket = make_ticket(key="AXG-99")
        scanner._queue_ticket(ticket, "TestClient", session="axian")

        resp = client.get("/api/jobs")
        keys = [j["ticket_key"] for j in resp.json()]
        assert "AXG-99" not in keys


# ---------------------------------------------------------------------------
# GET /api/ssh/status — session filtering
# ---------------------------------------------------------------------------

class TestSessionSshStatus:
    def test_axian_session_shows_primary_clients(self, client):
        main_mod.active_session = "axian"
        resp = client.get("/api/ssh/status")
        assert resp.status_code == 200
        assert "TestClient" in resp.json()

    def test_non_axian_session_shows_secondary_clients(self, client):
        _add_secondary()
        main_mod.active_session = "non_axian"
        resp = client.get("/api/ssh/status")
        assert resp.status_code == 200
        assert "CPEL" in resp.json()

    def test_non_axian_session_does_not_show_axian_clients(self, client):
        _add_secondary()
        main_mod.active_session = "non_axian"
        resp = client.get("/api/ssh/status")
        assert "TestClient" not in resp.json()


# ---------------------------------------------------------------------------
# _get_client() helper
# ---------------------------------------------------------------------------

class TestGetClient:
    def test_finds_primary_client(self):
        client_cfg, session = main_mod._get_client("TestClient")
        assert client_cfg is not None
        assert session == "axian"

    def test_finds_secondary_client(self):
        _add_secondary()
        client_cfg, session = main_mod._get_client("CPEL")
        assert client_cfg is not None
        assert session == "non_axian"

    def test_unknown_label_returns_none(self):
        client_cfg, session = main_mod._get_client("NoSuchClient")
        assert client_cfg is None
        assert session is None

    def test_returns_axian_over_secondary_for_same_label(self):
        """If somehow a label appears in both, axian takes precedence."""
        _add_secondary()
        # TestClient is primary; add it to secondary too
        main_mod.cfg.clients_secondary.append(
            ClientConfig(label="TestClient", name="Dup", kali_port=22,
                         kali_user="kali", kali_password="pass")
        )
        _, session = main_mod._get_client("TestClient")
        assert session == "axian"


# ---------------------------------------------------------------------------
# _jira_for_label() helper
# ---------------------------------------------------------------------------

class TestJiraForLabel:
    def test_axian_label_returns_primary_jira(self):
        result = main_mod._jira_for_label("TestClient")
        assert result is main_mod.jira

    def test_secondary_label_returns_jira_secondary(self):
        _add_secondary()
        result = main_mod._jira_for_label("CPEL")
        assert result is main_mod.jira_secondary

    def test_unknown_label_falls_back_to_primary_jira(self):
        result = main_mod._jira_for_label("UnknownClient")
        assert result is main_mod.jira


# ---------------------------------------------------------------------------
# _jira_for_job() helper
# ---------------------------------------------------------------------------

class TestJiraForJob:
    def test_axian_job_returns_primary_jira(self):
        job = {"session": "axian"}
        assert main_mod._jira_for_job(job) is main_mod.jira

    def test_non_axian_job_returns_secondary_jira(self):
        _add_secondary()
        job = {"session": "non_axian"}
        assert main_mod._jira_for_job(job) is main_mod.jira_secondary

    def test_job_without_session_field_defaults_to_axian(self):
        job = {}
        assert main_mod._jira_for_job(job) is main_mod.jira

    def test_non_axian_job_falls_back_to_primary_when_secondary_not_set(self):
        # jira_secondary is None (not configured)
        job = {"session": "non_axian"}
        assert main_mod._jira_for_job(job) is main_mod.jira


# ---------------------------------------------------------------------------
# scanner._queue_ticket — session tagging
# ---------------------------------------------------------------------------

class TestQueueTicketSession:
    def test_job_tagged_with_axian_by_default(self):
        ticket = make_ticket(key="AXG-100")
        job_id = scanner._queue_ticket(ticket, "TestClient")
        assert scanner.JOBS[job_id]["session"] == "axian"

    def test_job_tagged_with_axian_explicitly(self):
        ticket = make_ticket(key="AXG-101")
        job_id = scanner._queue_ticket(ticket, "TestClient", session="axian")
        assert scanner.JOBS[job_id]["session"] == "axian"

    def test_job_tagged_with_non_axian(self):
        ticket = make_ticket(key="CPEL-200")
        job_id = scanner._queue_ticket(ticket, "CPEL", session="non_axian")
        assert scanner.JOBS[job_id]["session"] == "non_axian"


# ---------------------------------------------------------------------------
# run_poll_cycle — session tagging
# ---------------------------------------------------------------------------

class TestPollCycleSessionTagging:
    def test_axian_poll_cycle_tags_jobs_as_axian(self):
        from src.scanner import run_poll_cycle
        mock_jira = MagicMock()
        mock_jira.SCANNABLE_TYPES = {"SCN", "IPT"}
        mock_jira.get_remediated_tickets.return_value = [make_ticket(key="AXG-300")]

        run_poll_cycle(main_mod.cfg, mock_jira, session="axian")

        axian_jobs = [j for j in scanner.JOBS.values() if j["ticket_key"] == "AXG-300"]
        assert len(axian_jobs) == 1
        assert axian_jobs[0]["session"] == "axian"

    def test_non_axian_poll_cycle_tags_jobs_as_non_axian(self):
        from src.scanner import run_poll_cycle
        _add_secondary()

        mock_jira2 = MagicMock()
        mock_jira2.SCANNABLE_TYPES = {"SCN", "IPT"}
        mock_jira2.get_remediated_tickets.return_value = [make_ticket(key="CPEL-400")]

        run_poll_cycle(main_mod.cfg, mock_jira2, session="non_axian")

        na_jobs = [j for j in scanner.JOBS.values() if j["ticket_key"] == "CPEL-400"]
        assert len(na_jobs) == 1
        assert na_jobs[0]["session"] == "non_axian"

    def test_non_axian_poll_uses_secondary_clients(self):
        from src.scanner import run_poll_cycle
        _add_secondary()

        mock_jira2 = MagicMock()
        mock_jira2.SCANNABLE_TYPES = {"SCN", "IPT"}
        mock_jira2.get_remediated_tickets.return_value = []

        run_poll_cycle(main_mod.cfg, mock_jira2, session="non_axian")

        mock_jira2.get_remediated_tickets.assert_called_once_with("CPEL")
