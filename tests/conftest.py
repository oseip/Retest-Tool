"""
Shared fixtures and session-wide patches.

src/main.py executes  cfg = load_config()  and  jira = JiraClient(cfg.jira)
at module import time.  The patches in pytest_configure / pytest_unconfigure
run before any test module is imported so those calls see mocks instead of
requiring a real config.yaml or Jira connection.
"""

import pytest
from unittest.mock import patch

from src.config import Config, JiraConfig, JumpServerConfig, ClientConfig
from src.config import load_config as _real_load_config  # captured before any patch is applied


# ---------------------------------------------------------------------------
# Test configuration helpers
# ---------------------------------------------------------------------------

def make_test_config() -> Config:
    return Config(
        jira=JiraConfig(
            url="https://test.atlassian.net",
            username="test@example.com",
            api_token="fake-api-token",
            project="TEST",
            retest_status="Remediated",
            poll_interval=60,
        ),
        jump_server=JumpServerConfig(
            host="jump.example.com",
            port=22,
            user="jumpuser",
            password="jumppass",
        ),
        clients=[
            ClientConfig(
                label="TestClient",
                name="Test Client",
                kali_port=2222,
                kali_user="kali",
                kali_password="kalipass",
            )
        ],
    )


def make_ticket(
    key="TEST-123",
    summary="SSL Certificate Expiry on 10.0.0.1",
    status="Remediated",
    ips=None,
    ports=None,
    cves=None,
) -> dict:
    return {
        "key": key,
        "summary": summary,
        "status": status,
        "ips": ips if ips is not None else ["10.0.0.1"],
        "ports": ports if ports is not None else ["443"],
        "cves": cves if cves is not None else [],
        "cvss": "7.5",
        "severity": "High",
        "technology": None,
        "labels": ["TestClient"],
        "updated": "2024-01-15T10:00:00.000",
        "description": "",
        "priority": "High",
        "assignee": None,
        "testtype": "SCN",
    }


# ---------------------------------------------------------------------------
# Session-wide patches — applied before any src.main import
# ---------------------------------------------------------------------------

# load_config and poll_jira stay patched for the entire session.
_load_cfg_patch = patch("src.config.load_config", return_value=make_test_config())
_poll_patch     = patch("src.scanner.poll_jira")


def pytest_configure(config):
    _load_cfg_patch.start()
    _poll_patch.start()

    # src/main.py runs  cfg = load_config()  and  jira = JiraClient(cfg.jira)
    # at module-import time.  Import it now, inside a temporary patch that
    # prevents a real Jira TCP connection, so the module is cached in
    # sys.modules before any test file imports it.
    # The temporary patch ends here, leaving src.jira_client.JiraClient as the
    # real class so that test_jira_client.py can exercise it directly.
    with patch("src.jira_client.JiraClient"), patch("src.jira_client.requests"):
        import src.main  # noqa: F401


def pytest_unconfigure(config):
    _load_cfg_patch.stop()
    _poll_patch.stop()


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def test_config():
    return make_test_config()


@pytest.fixture
def sample_ticket():
    return make_ticket()


@pytest.fixture(autouse=True)
def clean_scanner_state():
    """Wipe scanner module state before and after every test."""
    import src.scanner as scanner
    scanner.JOBS.clear()
    scanner.SEEN_KEYS.clear()
    scanner.APP_LOGS.clear()
    scanner._stop_events.clear()
    scanner._scan_queues.clear()
    scanner._scan_workers.clear()
    yield
    scanner.JOBS.clear()
    scanner.SEEN_KEYS.clear()
    scanner._stop_events.clear()
    scanner._scan_queues.clear()
    scanner._scan_workers.clear()
