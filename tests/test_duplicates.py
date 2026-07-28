"""Duplicate ticket detection — grouping across all Jira statuses."""

from unittest.mock import MagicMock, patch

import src.main as main_mod
from src.main import _duplicate_group_key
from tests.conftest import make_test_config


def _run_find_duplicates(tickets, session="axian", client="TestClient"):
    mock_jira = MagicMock()
    mock_jira.cfg.url = "https://test.atlassian.net"
    mock_jira.search_jql.return_value = tickets
    captured = {}

    def _capture_jql(jql, **kwargs):
        captured["jql"] = jql
        return tickets

    mock_jira.search_jql.side_effect = _capture_jql

    with patch.object(main_mod, "_jira_for_label", return_value=mock_jira), \
         patch.object(main_mod, "_get_client", return_value=(None, session)), \
         patch.object(main_mod, "cfg", make_test_config()):
        result = main_mod.find_duplicates(client)
    return result, captured.get("jql", "")


class TestDuplicateGroupKey:
    def test_scan_testtypes_ignore_affected_system(self):
        base = {
            "ips": ["10.0.0.1"],
            "ports": ["443"],
            "summary": "SSL Certificate Cannot Be Trusted",
            "affected_system": "app.example.com",
        }
        for tt in ("IPT", "SCN", "EPT", "ipt"):
            key = _duplicate_group_key({**base, "testtype": tt})
            assert key == ("10.0.0.1", "ssl certificate cannot be trusted", "443", "")

    def test_legacy_scan_without_testtype_ignores_affected(self):
        key = _duplicate_group_key({
            "ips": ["62.8.88.98"],
            "ports": ["5353"],
            "summary": "mDNS Detection (Remote Network)",
            "affected_system": "1dashboard.wananchi.com",
            "testtype": None,
        })
        assert key == ("62.8.88.98", "mdns detection (remote network)", "5353", "")

    def test_web_testtype_uses_affected_system(self):
        key = _duplicate_group_key({
            "ips": ["10.0.0.1"],
            "ports": ["443"],
            "summary": "Cross-Site Scripting",
            "affected_system": "Portal Login",
            "testtype": "WEB",
        })
        assert key == ("10.0.0.1", "cross-site scripting", "443", "portal login")


class TestFindDuplicates:
    def test_jql_includes_all_statuses_axian(self):
        _, jql = _run_find_duplicates([])
        assert "status NOT IN" not in jql
        assert 'labels = "TestClient"' in jql

    def test_jql_includes_all_statuses_non_axian(self):
        _, jql = _run_find_duplicates([], session="non_axian", client="CPEL")
        assert "status NOT IN" not in jql
        assert "project = CPEL" in jql

    def test_scan_tickets_group_despite_affected_system_mismatch(self):
        tickets = [
            {
                "key": "TEST-100",
                "summary": "mDNS Detection (Remote Network)",
                "status": "Fixed",
                "ips": ["62.8.88.98"],
                "ports": ["5353"],
                "affected_system": "1dashboard.wananchi.com",
                "testtype": "IPT",
            },
            {
                "key": "TEST-200",
                "summary": "mDNS Detection (Remote Network)",
                "status": "Reported",
                "ips": ["62.8.88.98"],
                "ports": ["5353"],
                "affected_system": "",
                "testtype": "IPT",
            },
        ]
        result, _ = _run_find_duplicates(tickets)
        assert result["total_groups"] == 1
        assert result["groups"][0]["keep"] == "TEST-100"

    def test_web_tickets_split_on_affected_system(self):
        tickets = [
            {
                "key": "TEST-100",
                "summary": "Cross-Site Scripting",
                "status": "Open",
                "ips": ["10.0.0.1"],
                "ports": ["443"],
                "affected_system": "Admin Portal",
                "testtype": "WEB",
            },
            {
                "key": "TEST-200",
                "summary": "Cross-Site Scripting",
                "status": "Open",
                "ips": ["10.0.0.1"],
                "ports": ["443"],
                "affected_system": "User Portal",
                "testtype": "WEB",
            },
        ]
        result, _ = _run_find_duplicates(tickets)
        assert result["total_groups"] == 0

    def test_web_tickets_group_with_same_affected_system(self):
        tickets = [
            {
                "key": "TEST-100",
                "summary": "Cross-Site Scripting",
                "status": "Fixed",
                "ips": ["10.0.0.1"],
                "ports": ["443"],
                "affected_system": "Admin Portal",
                "testtype": "WEB",
            },
            {
                "key": "TEST-200",
                "summary": "Cross-Site Scripting",
                "status": "Open",
                "ips": ["10.0.0.1"],
                "ports": ["443"],
                "affected_system": "Admin Portal",
                "testtype": "WEB",
            },
        ]
        result, _ = _run_find_duplicates(tickets)
        assert result["total_groups"] == 1
        assert result["groups"][0]["keep"] == "TEST-100"
